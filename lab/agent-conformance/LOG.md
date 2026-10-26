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

## 010 — operator in a throwaway home, source discovery

Runtime owns the fixture operator and its provider processes. Task 003 takes
its live-or-BLOCKED decision from the single verdict in
[GAPS.md: Operator in a throwaway home](GAPS.md#operator-in-a-throwaway-home).
AC-010-OFFLINE stays open: Carrier's loopback bind and environment-only LAN
discovery control are separate. The lane supplies exactly HOME, TMPDIR and
PATH (`src/harness.rs:201-207`; `tests/harness.rs:82-105`). The verdict names
the Home-config change needed for this fixture; live traffic proof is pending.

Plain `serve` requires a verified `bin/localhost-provider` and its
`components.json` entry. DID and shell are optional on this path; the managed
Home list is separate (`elastos/crates/elastos-server/src/server_infra.rs:740-806`;
`serve_cmd.rs:327-366`; `runtime_control.rs:1269-1291` in that server directory).
GAPS records manifest fields, SHA-256 verification and offline build commands.
Provider compilation and cache completeness remain unmeasured.

The file table covers the host lock, config, device identity, capability state,
TLS files, canonical roots, installed binary and coordinates. Keys appear by
file name and role only. A fresh Home has an empty community bootstrap list
(`collaboration_startup.rs:78-89,164-180`); passing that list alone proves no dial.

Readiness requires coordinates plus live loopback health before `run` performs
its own attach checks (`serve_cmd.rs:437-446`; `runtime_control.rs:769-810`).
SIGTERM reaches the owned process group, with a two-second forced-stop bound
(`main.rs:1284-1322`). `serve --storage-path` can select an in-root directory;
AC-006-STORAGE remains attached to `run`'s fixed constructor (`serve_cmd.rs:47`;
`run_cmd.rs:236`). An unsigned source probe requires Home-local `dev_mode = true`
and remains subject to grants (`runtime.rs:181-227`).

Checks ran offline with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`:

| Command | Result |
| --- | --- |
| `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` | Exit 0. |
| `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` | Exit 0; 10 passed, 0 failed, 0 ignored. |
| `git diff --check` | Exit 0. |
| `node scripts/check-product-data.mjs` and `node --test scripts/check-product-data.test.mjs` | 42 capsules, 2 profiles, 28 method contracts; 99 tests passed. |
| `(cd elastos && cargo fmt --all -- --check)` and chain-provider formatting | Both exit 0. |

Cargo used `CARGO_NET_OFFLINE=true`; target, intermediate and temporary outputs
stayed in this lane's `target/`. The required suite built the probe twice.
Runtime/provider builds, Runtime launches and network calls: zero. New tests
and falsifiers: zero; this documentation change leaves executable rules intact.
Existing falsifiers were unchanged and were not rerun.

The worktree began clean; generated check artifacts were removed. GAPS and LOG
remain for the supervisor's commit, so `git status --short` lists those two
edits. Cached upstream comparison is 0 ahead / 0 behind
`spike/spike/agent-host`; remote freshness is unverified. Git state is unchanged.

Principles check (paths without a prefix below are relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name/URL where a hash belongs? | No. Provider code is identified by its installed byte checksum; `GAPS.md:157-169`. |
| 2. New ambient or UI authority? | No. The existing launch environment stays fixed; `src/harness.rs:201-207`. |
| 3. Second operation path or rule copy? | No. This summary links the one operator verdict; `GAPS.md:83-92`. |
| 4. Does the trusted core grow? | No. The Runtime change is an open blocker, with zero Runtime edits; `GAPS.md:85`. |
| 5. Clear fail-closed refusal? | Yes. 003 is explicitly BLOCKED pending the Home-config control and traffic proof; `GAPS.md:85`. |
| 6. Capsule logic stays inside and traps down? | Yes. The typed Bus entry and internal refusal are unchanged; `probe/src/lib.rs:8-25`. |
| 7. New executable rules have tests and caught falsifiers? | Yes within documentation scope: zero new executable rules. The existing environment test stays intact; `tests/harness.rs:82-105`. This discovery claims no new falsifier result. |

- 010: Extended the single GAPS record and this summary with operator startup files, provider checks/build commands, network controls, readiness/stop/admission evidence and AC-010-OFFLINE; clarified the separate AC-006-STORAGE scope.

## 009 — Runtime identity and contained no-operator launch

- 009: Added `build::offline_build` and `runtime::runtime_under_test`, reused the shared build setup in `tests/artifact.rs::build_probe`, added two Runtime checks and F-ac1f/F-ac1g, printed the Runtime hash above the existing table, and updated README, RUNBOOK and GAPS.

The Runtime build uses its normal toolchain environment and the exact command
`cargo build --locked --offline --manifest-path elastos/Cargo.toml -p elastos-server --bin elastos`.
`OnceLock` caches either its result or its error once per test process. Build
outputs stay under `target/runtime`, including `build/` and `tmp/`; debug info
and incremental compilation are disabled. The std-only harness hashes the
binary with macOS `shasum`; the existing `sha2` test dependency independently
checks the returned digest. Cargo manifests and lockfiles stay unchanged.
The binary's path locates it, and its computed SHA-256 identifies the tested
bytes. This hash is specific to this machine and toolchain, as with 002's probe.

The initial run found an existing warm target. For a real cold measurement,
under the shared heavy-build lease, the builder checked the previous binary
with `lsof`, removed only `target/runtime`, and ran:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime -- --show-output
```

Cold Runtime build plus SHA-256: **138.47 seconds**. The complete two-test
command took **143.05 seconds**, with 2 passed, 0 failed and 0 ignored.
`du -sk lab/agent-conformance/target/runtime` reported **2092432 KiB**
(1.995 GiB), including intermediates. The free-space check allowed
12 GiB of generated files plus a 2 GiB reserve. The warm target stays for the
supervisor's gate, then its local inventory entry requires removal.

Every Runtime launch uses `ThrowawayHome::launch`. The relative probe locator
resolves to this lane's probe from the throwaway Home and keeps private
checkout paths out of the Runtime transcript. The no-operator test checks the
nonzero exit and Runtime reason. The data-dir test writes dummy coordinates
at `home.data()`; Runtime removes them and returns the same reason. Runtime
rejects the documentation-address URL before PID checks or network calls.
The operator lookup returns before storage construction. AC-006-STORAGE and
all other GAPS blockers remain open; this is refusal proof only.

Exact stderr from the restored no-operator check, in lossless Rust string
escaping (`\u{1b}` is ESC and `\n` is a newline):

```text
"\u{1b}[2m2026-10-25T15:57:49.974117Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::run_cmd\u{1b}[0m\u{1b}[2m:\u{1b}[0m Running capsule from: ../../../probe\nError: This command requires a running runtime.\n\n  elastos serve\n\nThen run this command again.\n"
```

The commands below used the repository's existing `fcntl.flock` heavy-build
lease and these build settings from the repository root:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-009"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

Each falsifier's single edit came from `falsifiers.json`. The builder asserted
one exact match, applied `original.replace(old, new, 1)`, ran the named test,
restored the original bytes in `finally`, then reran the same command.
Every named test ran and failed on its assertion (exit 101), then passed
(exit 0). In the captured output below, raw ESC bytes are shown as `\x1b`.
The shared falsifier runner stays unchanged.

F-ac1g uses the recognized non-component ABI `wasi-preview1`. In this checkout,
`manifest.rs:738-742` rejects that ABI before the branch cited in the task at
`run_cmd.rs:52-56`. The observed reason is `Invalid manifest: WASI Preview 1 is
not a supported product capsule ABI; use elastos.component/v1 or
elastos.runtime-projection/v1`. The test therefore proves reason matching
against Runtime's actual refusal. A preliminary misspelling reached enum
parsing instead; it was corrected and is excluded from the evidence below.

**F-ac1f**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime runtime_data_dir_is_under_throwaway_home -- --exact --nocapture
```

Planted (exit 101):

```text

running 1 test
elastos build finished in 0.88s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd

thread 'runtime_data_dir_is_under_throwaway_home' (21647373) panicked at tests/runtime.rs:71:5:
Runtime must remove the decoy from the guarded data directory
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-68327-1792943743314015000-0
runtime_data_dir_is_under_throwaway_home --- FAILED

failures:

failures:
    runtime_data_dir_is_under_throwaway_home

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 2.02s

error: test failed, to rerun pass `-p agent-conformance --test runtime`
```

Restored (exit 0):

```text

running 1 test
elastos build finished in 0.61s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.80s
```

**F-ac1g**

```sh
cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime run_without_operator_is_refused_with_reason -- --exact --nocapture
```

Planted (exit 101):

```text

running 1 test
elastos build finished in 0.59s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd

thread 'run_without_operator_is_refused_with_reason' (21672888) panicked at tests/runtime.rs:35:5:
expected operator refusal; stderr:
\x1b[2m2026-10-25T15:57:43.137657Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos::run_cmd\x1b[0m\x1b[2m:\x1b[0m Running capsule from: ../../../probe
Error: Invalid manifest: WASI Preview 1 is not a supported product capsule ABI; use elastos.component/v1 or elastos.runtime-projection/v1

note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-72450-1792943856125151000-0
run_without_operator_is_refused_with_reason --- FAILED

failures:

failures:
    run_without_operator_is_refused_with_reason

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 12.32s

error: test failed, to rerun pass `-p agent-conformance --test runtime`
```

Restored (exit 0):

```text

running 1 test
elastos build finished in 0.69s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
Runtime refusal stderr: "\u{1b}[2m2026-10-25T15:57:49.974117Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::run_cmd\u{1b}[0m\u{1b}[2m:\u{1b}[0m Running capsule from: ../../../probe\nError: This command requires a running runtime.\n\n  elastos serve\n\nThen run this command again.\n"
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 6.78s
```

Final lane checks passed with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

The full Cargo command took 40.50 seconds; the table command took 34.57 seconds.
Both completed with 12 passed, 0 failed and 0 ignored. The exact table:

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

The basic repository gate also passed: `git diff --check`, the product-data
check (42 capsules, 2 profiles, 28 method contracts), its 99 tests, Runtime
workspace formatting and chain-provider formatting. `bash -n` passed for
`run.sh`. All 12 falsifier IDs are unique and all exact edit anchors match.
The ten unchanged falsifiers were checked for anchor validity; their mutations
were outside this task's rerun scope. Their normal tests passed in the suite.

Source SHA-256 values and `git status --porcelain` were unchanged by the full
runs and falsifier restoration. The builder leaves only lane source edits for
the supervisor's commit; an empty status follows that commit. Generated files
are ignored. The restored probe and harness have zero source diff. The two
intentional failure roots remain for supervisor review, then removal under
the local lifecycle inventory. Each child was waited for; this task started
only bounded CLI commands. The cached `spike/spike/agent-host` upstream moved
during verification; the final branch inventory is 0 ahead / 3 behind it.
Remote freshness is unverified under the network restriction. Commit, push, PR evidence and independent review belong
to the supervisor. These exact commands and outputs are ready for its PR.

Principles check (paths are relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name/URL where a code/content hash belongs? | No. `src/runtime.rs:55-79` computes and returns the built binary's SHA-256; the path only locates those bytes. |
| 2. New ambient or UI authority? | No. `tests/runtime.rs:23-29` uses the existing guarded launch, whose cleared environment is at `src/harness.rs:204`; the probe receives no grant. |
| 3. Second operation path or rule copy? | No. `src/build.rs:17` owns the shared offline setup; `tests/artifact.rs:17` reuses it, and `tests/runtime.rs:64` uses the existing data-dir rule. |
| 4. Does the trusted core grow? | No. The new modules are exported from the lane at `src/lib.rs:3-6`; the Runtime tree has zero source changes. |
| 5. Does refusal fail closed with a reason? | Yes. `tests/runtime.rs:31-37` requires both the failed exit and Runtime's exact reason fragment; `src/runtime.rs:47-53` preserves Cargo failure output. |
| 6. Does capsule logic stay inside and trap down? | Yes. The probe remains unchanged with typed Bus bindings at `probe/src/lib.rs:8` and its internal refusal at `probe/src/lib.rs:14`. |
| 7. Do new rules have tests and caught falsifiers? | Yes. `tests/runtime.rs:43` and `tests/runtime.rs:60` passed, failed under F-ac1g/F-ac1f, then passed after restoration; `falsifiers.json:166` and `falsifiers.json:182` hold the exact edits. |

## 011 — 009 re-landed on the moved base

- 011: Restored the nine reviewed files byte-identical to `0f84602e6`, kept all 010 text in GAPS and LOG, and appended 009's exact LOG section before this record.

The base guard passed before edits. GAPS has +21/-14 against the task base
and +204/-0 against 009; its 204 added lines exactly match 010's additions.
LOG keeps the complete task-base prefix and the reviewed 215-line appendix.
The existing shared heavy-build lease was held for all lane checks. Commands
ran from the repository root with:

```sh
export CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-011/tmp"
```

Each falsifier was applied once from its exact `falsifiers.json` edit after
checking one matching anchor. Original bytes were restored in `finally`, then
the same named test ran again. Both commands below ran planted and restored:

| Falsifier and command | Result |
| --- | --- |
| F-ac1f: `cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime runtime_data_dir_is_under_throwaway_home -- --exact --nocapture` | Planted: exit 101, 1 failed because Runtime left the decoy in the wrong data directory; restored: exit 0, 1 passed. |
| F-ac1g: `cargo test --quiet --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime run_without_operator_is_refused_with_reason -- --exact --nocapture` | Planted: exit 101, 1 failed because Runtime returned the WASI Preview 1 manifest refusal instead of the operator refusal; restored: exit 0, 1 passed. |

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` passed.
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -- --show-output`
passed: 12 passed, 0 failed, 0 ignored, in 45.51 seconds. `lab/agent-conformance/run.sh`
passed in 44.87 seconds, with the Runtime hash above all 12 PASS rows.
The warm Runtime build plus SHA-256 took 1.54 seconds. Runtime SHA-256:
`150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd`.

The basic gate passed: `git diff --check`, `node scripts/check-product-data.mjs`
(42 capsules, 2 profiles, 28 method contracts), its 99 tests, Runtime workspace
formatting and chain-provider formatting. `bash -n lab/agent-conformance/run.sh`
also passed. These checks used the existing tests and falsifiers unchanged.

Source hashes and Git status were identical before and after the runs.
The supervisor owns staging and committing the 11 source files; three are
new, so Git's index-based diff omits their working bytes until staging.
Direct comparisons with `git show 0f84602e6:<path>` prove all nine reviewed
files match. An empty Git status awaits that supervisor commit. Cached
upstream divergence is 0 ahead / 0 behind; remote freshness is unverified
under the network restriction. Ignored build outputs and the two failed-test
roots have removal conditions in the local lifecycle inventory.


## 012 — first serve refuses a provider whose bytes differ from its hash

- 012: Added the cached provider build, shared operator-Home writer, checksum-refusal test and F-ac1i; the runner shows both native hashes.

Runtime owns provider admission. `localhost_provider_under_test()` shares
`build_native` and `sha256_file` with the Runtime helper. Each native result,
including failure, is cached once per process. `tests/common::write_operator_home`
runs the Home guard first, copies executable bytes, and writes only the source
manifest's localhost-provider entry plus empty profiles. The current Mac
platform receives the copied bytes' SHA-256, size and install path. The source
entry owns the other fields. The fixture supports both Mac platform keys;
this run exercised darwin-arm64.

The test appends one byte, launches through the existing primitive with a
10-second bound, and requires the checksum reason. It also requires in-root
storage and an absent readiness file. The normal and planted launches stop
at provider verification, before Carrier and HTTP startup. The test reserves
and closes a free loopback port without connecting. Task 013 owns the ready
operator; the AC-010-OFFLINE verdict and other GAPS blockers remain unchanged.

The existing native target was warm. The first successful refusal check measured
localhost-provider build plus SHA-256 at **0.12 seconds** and Runtime at
**0.82 seconds**. `du -sk lab/agent-conformance/target/runtime` reported
**2183616 KiB** afterwards. These are cached-build measurements. The volume
had 36159464 KiB free before the build, above the 12 GiB estimate plus the
2 GiB reserve. The supervisor's rerun owns the retained build outputs and
their removal condition in the local lifecycle inventory.

The first sandboxed attempt stopped at the test's loopback bind with
`Operation not permitted`, before Runtime launch. The authorized local-bind
rerun passed. All commands below held the repository's existing heavy-build
lease and used these settings from the repository root:

```sh
export CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-012/tmp"
```

F-ac1i changes only the writer's installed filename to
`bin/localhost-provider-copy`; the manifest continues to name
`bin/localhost-provider`. The test appends its byte to the returned copy.
Runtime therefore reports a missing provider, and the test fails on its
checksum-reason assertion. The provider bytes remain mismatched in both
cases, so the falsifier cannot advance startup to Carrier.

The exact test command, run once with the edit planted and once after restoration:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime serve_refuses_provider_whose_bytes_differ_from_its_hash -- --exact --nocapture
```

The mutation and restoration used the list's exact edit with one matching anchor:

```python
item = next(f for f in json.loads((lane / 'falsifiers.json').read_text())['falsifiers'] if f['id'] == 'F-ac1i')
edit = item['edits'][0]
path = lane / edit['file']
original = path.read_bytes()
assert original.count(edit['old'].encode()) == 1
try:
    path.write_bytes(original.replace(edit['old'].encode(), edit['new'].encode(), 1))
    # Run the exact Cargo command above and require exit 101, the named test's
    # failed result, and the missing-provider reason at the checksum assertion.
finally:
    path.write_bytes(original)
# Run the same Cargo command again and require exit 0.
```

Exact planted output (exit 101). Raw ESC bytes appear as `\x1b`; the test's
stderr string uses lossless Rust escapes. `<lane>` replaces the absolute
lane directory prefix throughout these transcripts:

```text
   Compiling agent-conformance v0.1.0 (<lane>)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.40s
     Running tests/runtime.rs (lab/agent-conformance/target/host-build/debug/deps/runtime-c27987e729dd278e)

running 1 test
elastos build finished in 0.90s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider build finished in 0.13s
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
Provider refusal stderr: "\u{1b}[2m2026-10-25T20:01:34.271610Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos\u{1b}[0m\u{1b}[2m:\u{1b}[0m open-file soft limit 1048575 (was 1048575)\nElastOS Runtime v0.8.0-dev starting on 127.0.0.1:60893\n\u{1b}[2m2026-10-25T20:01:34.604617Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::serve_cmd\u{1b}[0m\u{1b}[2m:\u{1b}[0m Starting ElastOS Runtime server v0.8.0-dev on 127.0.0.1:60893\n\u{1b}[2m2026-10-25T20:01:34.605184Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_server::runtime\u{1b}[0m\u{1b}[2m:\u{1b}[0m Capsule signatures enforced with 0 trusted key(s)\n\u{1b}[2m2026-10-25T20:01:34.623652Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::capability::manager\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generated and saved new capability signing key to \"<lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/signing_key\"\n\u{1b}[2m2026-10-25T20:01:34.623901Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generating new ElastOS CA certificate...\n\u{1b}[2m2026-10-25T20:01:34.624431Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m CA certificate written to <lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/ca.pem\n\u{1b}[2m2026-10-25T20:01:34.624438Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Trust this CA on your devices: elastos tls trust\n\u{1b}[2m2026-10-25T20:01:34.625873Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Detected IPs for TLS cert: [\"127.0.0.1\"]\n\u{1b}[2m2026-10-25T20:01:34.625899Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generating TLS leaf certificate...\n\u{1b}[2m2026-10-25T20:01:34.626265Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m TLS leaf certificate written to <lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/tls.pem\n\u{1b}[2m2026-10-25T20:01:34.626599Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::server_infra\u{1b}[0m\u{1b}[2m:\u{1b}[0m TLS enabled (self-signed CA)\n\u{1b}[2m2026-10-25T20:01:34.627336Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'content-provider' for scheme 'content'\n\u{1b}[2m2026-10-25T20:01:34.627502Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered sub-provider 'content-provider' for elastos://content/...\n\u{1b}[2m2026-10-25T20:01:34.627584Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'documents-provider' for scheme 'documents'\n\u{1b}[2m2026-10-25T20:01:34.627619Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'inspect' for scheme 'inspect'\n\u{1b}[2m2026-10-25T20:01:34.627634Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered sub-provider 'inspect' for elastos://inspect/...\nError: localhost-provider not installed.\n  Run:\n  elastos setup --with localhost-provider\n"

thread 'serve_refuses_provider_whose_bytes_differ_from_its_hash' (23392766) panicked at tests/runtime.rs:147:5:
expected provider checksum refusal; stderr:
\x1b[2m2026-10-25T20:01:34.271610Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos\x1b[0m\x1b[2m:\x1b[0m open-file soft limit 1048575 (was 1048575)
ElastOS Runtime v0.8.0-dev starting on 127.0.0.1:60893
\x1b[2m2026-10-25T20:01:34.604617Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos::serve_cmd\x1b[0m\x1b[2m:\x1b[0m Starting ElastOS Runtime server v0.8.0-dev on 127.0.0.1:60893
\x1b[2m2026-10-25T20:01:34.605184Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_server::runtime\x1b[0m\x1b[2m:\x1b[0m Capsule signatures enforced with 0 trusted key(s)
\x1b[2m2026-10-25T20:01:34.623652Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::capability::manager\x1b[0m\x1b[2m:\x1b[0m Generated and saved new capability signing key to "<lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/signing_key"
\x1b[2m2026-10-25T20:01:34.623901Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m Generating new ElastOS CA certificate...
\x1b[2m2026-10-25T20:01:34.624431Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m CA certificate written to <lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/ca.pem
\x1b[2m2026-10-25T20:01:34.624438Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m Trust this CA on your devices: elastos tls trust
\x1b[2m2026-10-25T20:01:34.625873Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m Detected IPs for TLS cert: ["127.0.0.1"]
\x1b[2m2026-10-25T20:01:34.625899Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m Generating TLS leaf certificate...
\x1b[2m2026-10-25T20:01:34.626265Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_tls\x1b[0m\x1b[2m:\x1b[0m TLS leaf certificate written to <lane>/target/home-52945-1792958493000767000-0/home/Library/Application Support/elastos/tls.pem
\x1b[2m2026-10-25T20:01:34.626599Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos::server_infra\x1b[0m\x1b[2m:\x1b[0m TLS enabled (self-signed CA)
\x1b[2m2026-10-25T20:01:34.627336Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::provider::registry\x1b[0m\x1b[2m:\x1b[0m Registered provider 'content-provider' for scheme 'content'
\x1b[2m2026-10-25T20:01:34.627502Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::provider::registry\x1b[0m\x1b[2m:\x1b[0m Registered sub-provider 'content-provider' for elastos://content/...
\x1b[2m2026-10-25T20:01:34.627584Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::provider::registry\x1b[0m\x1b[2m:\x1b[0m Registered provider 'documents-provider' for scheme 'documents'
\x1b[2m2026-10-25T20:01:34.627619Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::provider::registry\x1b[0m\x1b[2m:\x1b[0m Registered provider 'inspect' for scheme 'inspect'
\x1b[2m2026-10-25T20:01:34.627634Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2melastos_runtime::provider::registry\x1b[0m\x1b[2m:\x1b[0m Registered sub-provider 'inspect' for elastos://inspect/...
Error: localhost-provider not installed.
  Run:
  elastos setup --with localhost-provider

note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
retained throwaway root: lab/agent-conformance/target/home-52945-1792958493000767000-0
test serve_refuses_provider_whose_bytes_differ_from_its_hash ... FAILED

failures:

failures:
    serve_refuses_provider_whose_bytes_differ_from_its_hash

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 2.54s

error: test failed, to rerun pass `-p agent-conformance --test runtime`
```

Exact restored output (exit 0), including the complete Runtime checksum-refusal stderr:

```text
   Compiling agent-conformance v0.1.0 (<lane>)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.16s
     Running tests/runtime.rs (lab/agent-conformance/target/host-build/debug/deps/runtime-c27987e729dd278e)

running 1 test
elastos build finished in 0.58s
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider build finished in 0.11s
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
Provider refusal stderr: "\u{1b}[2m2026-10-25T20:01:37.111530Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos\u{1b}[0m\u{1b}[2m:\u{1b}[0m open-file soft limit 1048575 (was 1048575)\nElastOS Runtime v0.8.0-dev starting on 127.0.0.1:60897\n\u{1b}[2m2026-10-25T20:01:37.432711Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::serve_cmd\u{1b}[0m\u{1b}[2m:\u{1b}[0m Starting ElastOS Runtime server v0.8.0-dev on 127.0.0.1:60897\n\u{1b}[2m2026-10-25T20:01:37.433276Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_server::runtime\u{1b}[0m\u{1b}[2m:\u{1b}[0m Capsule signatures enforced with 0 trusted key(s)\n\u{1b}[2m2026-10-25T20:01:37.452764Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::capability::manager\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generated and saved new capability signing key to \"<lane>/target/home-53339-1792958495814064000-0/home/Library/Application Support/elastos/signing_key\"\n\u{1b}[2m2026-10-25T20:01:37.453007Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generating new ElastOS CA certificate...\n\u{1b}[2m2026-10-25T20:01:37.453531Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m CA certificate written to <lane>/target/home-53339-1792958495814064000-0/home/Library/Application Support/elastos/ca.pem\n\u{1b}[2m2026-10-25T20:01:37.453536Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Trust this CA on your devices: elastos tls trust\n\u{1b}[2m2026-10-25T20:01:37.455197Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Detected IPs for TLS cert: [\"127.0.0.1\"]\n\u{1b}[2m2026-10-25T20:01:37.455218Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m Generating TLS leaf certificate...\n\u{1b}[2m2026-10-25T20:01:37.455508Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_tls\u{1b}[0m\u{1b}[2m:\u{1b}[0m TLS leaf certificate written to <lane>/target/home-53339-1792958495814064000-0/home/Library/Application Support/elastos/tls.pem\n\u{1b}[2m2026-10-25T20:01:37.455806Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos::server_infra\u{1b}[0m\u{1b}[2m:\u{1b}[0m TLS enabled (self-signed CA)\n\u{1b}[2m2026-10-25T20:01:37.456310Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'content-provider' for scheme 'content'\n\u{1b}[2m2026-10-25T20:01:37.456444Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered sub-provider 'content-provider' for elastos://content/...\n\u{1b}[2m2026-10-25T20:01:37.456511Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'documents-provider' for scheme 'documents'\n\u{1b}[2m2026-10-25T20:01:37.456539Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered provider 'inspect' for scheme 'inspect'\n\u{1b}[2m2026-10-25T20:01:37.456550Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2melastos_runtime::provider::registry\u{1b}[0m\u{1b}[2m:\u{1b}[0m Registered sub-provider 'inspect' for elastos://inspect/...\nError: installed component 'localhost-provider' at <lane>/target/home-53339-1792958495814064000-0/home/Library/Application Support/elastos/bin/localhost-provider failed checksum verification against <lane>/target/home-53339-1792958495814064000-0/home/Library/Application Support/elastos/components.json\n"
test serve_refuses_provider_whose_bytes_differ_from_its_hash ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 2.24s

```

Final lane checks, all exit 0:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

The full test command took **41.68 seconds** and the
report command took **37.31 seconds**. Each ran
13 tests: 13 passed, 0 failed, 0 ignored. The unchanged Home guard and complete
environment tests passed. Exact report output:

```text
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
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
serve_refuses_provider_whose_bytes_differ_from_its_hash | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
```

The basic repository gate passed: `git diff --check`, the product-data check
(42 capsules, 2 profiles, 28 method contracts), its 99 tests, Runtime workspace
formatting and chain-provider formatting. `bash -n lab/agent-conformance/run.sh`
also passed. All 13 falsifier IDs are unique and their edit anchors match
exactly once. F-ac1i was the new mutation run; earlier falsifiers retain their
recorded proof, and their normal tests passed here.

Source bytes and `git status --porcelain` were unchanged across the gates.
The worktree started clean; its remaining source edits are this task's candidate.
An empty Git status awaits the supervisor's commit, because this builder's
instructions reserve all Git mutations for the supervisor. Cached upstream
was 0 ahead / 4 behind at the final check; remote freshness remains unverified
under the network restriction. The supervisor owns integration and the PR;
the F-ac1i command and transcripts above are ready for its review record.
The two failed-test roots were removed after result review and empty open-file
checks. Passed roots remove themselves through the existing harness. The local
lifecycle inventory records the retained build and proof cleanup conditions.

Principles check (paths below are relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name/URL in place of a code/content hash? | No. `src/runtime.rs:65` computes the binary hash; `tests/common/mod.rs:44` stamps the installed copy's hash. Names locate the entry and file. |
| 2. New ambient or UI authority? | No. `tests/runtime.rs:127` uses the existing guarded launch; `src/harness.rs:205` retains the three-entry environment. |
| 3. A second path or copy of a rule? | No. `src/runtime.rs:35` owns both native builds, `src/runtime.rs:75` owns hashing, and `tests/common/mod.rs:21` owns the operator fixture. |
| 4. Does the trusted Runtime core grow? | No. All changed source stays under this lane; `tests/runtime.rs:128` runs the existing binary as a black box. |
| 5. Does refusal fail closed with a reason? | Yes. `tests/runtime.rs:143` requires a failed exit and `tests/runtime.rs:148` requires the checksum reason. |
| 6. Does capsule logic stay inside and trap down through grants? | Yes. The probe stays unchanged; `probe/src/lib.rs:8` retains its typed Bus bindings. This task changes fixture code only. |
| 7. Do tests and a caught falsifier prove the new rule? | Yes. `tests/runtime.rs:83` passed, failed on its reason check under F-ac1i, then passed restored; `falsifiers.json:198` owns the edit. |

## 014 — 012 re-landed on the moved base

- 014: Restored 012's eight reviewed files from `622cf488f`; added this fresh F-ac1i result and the exact edit commands.

Both guards passed at base `de37cb412`: the lane diff from `c6709039d` was
empty, and `tests/common/mod.rs` was absent. The seven required files match
`622cf488f` byte for byte. This section follows the complete, unchanged 012 log.
The supervisor owns the commit and the checks against that committed head.

All lane runs held the shared heavy-build lease and used 012's settings:

```sh
export CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-012/tmp"
```

The volume had 35797712 KiB free before the runs, above the 12 GiB build
estimate plus the 2 GiB reserve. Both native binaries were already cached.
A sandbox preflight refused the loopback bind before Runtime launch; the
runs below used the approved local-bind permission. Cargo stayed offline.
Both serve cases stopped at provider verification, before Carrier startup.

Exact shell commands, in execution order (restoration ran in a `finally`
block around the planted test):

```sh
python3 - <<'EDIT'
import json
from pathlib import Path
lane = Path('lab/agent-conformance')
item = next(f for f in json.loads((lane / 'falsifiers.json').read_text())['falsifiers'] if f['id'] == 'F-ac1i')
assert len(item['edits']) == 1
edit = item['edits'][0]
path = lane / edit['file']
original = path.read_bytes()
assert original.count(edit['old'].encode()) == 1
assert original.count(edit['new'].encode()) == 0
path.write_bytes(original.replace(edit['old'].encode(), edit['new'].encode(), 1))
print('F-ac1i planted; exact anchor count: 1')
EDIT
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime serve_refuses_provider_whose_bytes_differ_from_its_hash -- --exact --nocapture
python3 - <<'EDIT'
import json
from pathlib import Path
import subprocess
lane = Path('lab/agent-conformance')
item = next(f for f in json.loads((lane / 'falsifiers.json').read_text())['falsifiers'] if f['id'] == 'F-ac1i')
edit = item['edits'][0]
path = lane / edit['file']
original = subprocess.check_output(['git', 'show', '622cf488f:' + path.as_posix()])
assert path.read_bytes() == original.replace(edit['old'].encode(), edit['new'].encode(), 1)
path.write_bytes(original)
print('F-ac1i restored byte for byte from 622cf488f')
EDIT
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime serve_refuses_provider_whose_bytes_differ_from_its_hash -- --exact --nocapture
```

| Run | Exit | Result | Provider build plus SHA-256 |
| --- | --- | --- | --- |
| F-ac1i planted once | 101 | The sole named test failed at `tests/runtime.rs:147`: checksum reason expected, `localhost-provider not installed.` received. | 0.13 s, warm |
| Exact bytes restored | 0 | The same test passed: 1 passed, 0 failed, 0 ignored. | 0.15 s, warm |

Both runs reported these exact binary identities:

```text
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
```

Final gates, each exit 0:

| Command | Result |
| --- | --- |
| `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` | PASS |
| `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` | 13 passed, 0 failed, 0 ignored; 44.83 s |
| `lab/agent-conformance/run.sh` | Both hashes above the table; all 13 rows PASS; 36.59 s |

The basic repository gate also passed: `git diff --check`, product-data
validation (42 capsules, 2 profiles, 28 method contracts), all 99 product-data
tests, Runtime workspace formatting and chain-provider formatting.
`bash -n lab/agent-conformance/run.sh` passed. Gate runs preserved candidate
bytes and Git status; the eight task files are the only visible changes.
The failed-test Home was removed after result review and an empty open-file
check; passing Homes removed themselves. Ignored build and proof outputs stay
for the supervisor rerun, with its cleanup condition in the local inventory.
The fetched upstream is 0 ahead / 0 behind; remote freshness awaits the
supervisor's network-enabled check. This builder kept Git state unchanged.

## 013 — ready operator in an offline throwaway Home

- 013: Extended the one launch primitive with fixed mDNS-off environment and managed process groups; added the matching-provider operator recipe, measured socket census, stop proof and five caught falsifiers.

`ThrowawayHome::spawn` owns the guard, four-entry environment, null stdin,
capture files and `process_group(0)` for both launch forms. `start` returns a
`RunningChild`; its stop path sends SIGTERM, checks the ten-second bound and
requires the whole group to exit. Timeout and abandoned-handle paths kill the
group and retain the root. `kill`, `pgrep` and `lsof` use that same primitive.
The shared writer adds the committed two-setting config. `Operator::ready`
checks coordinates existence and loopback HTTP 200 while the child stays alive.
The coordinates and operator capture contents stay unread.

Both operator tests passed. The census saw two loopback internet sockets in
each sample, including the API listener, at least three seconds apart. This
closes AC-010-OFFLINE for this fixture. It also closes 012's platform-key
positive-control gap: matching installed provider bytes reached readiness.
The census samples the process group's internet sockets at those times; it
is not a packet capture. AC-006-STORAGE remains open for `run`.

Five new tests are named in `tests/runtime.rs` and `tests/harness.rs`:
`fixture_operator_starts_ready_and_stops_cleanly`,
`fixture_operator_sockets_are_loopback_only`,
`socket_census_requires_parseable_loopback_endpoints_and_api_listener`,
`managed_child_stop_reaps_its_process_group`, and
`managed_child_drop_kills_its_group_and_keeps_root`.
The existing environment test now requires exactly four entries.

The volume had 34 GiB free before the runs, above the 12 GiB build estimate
plus 2 GiB reserve. Builds used the existing native cache. Every Cargo run
held the repository's shared heavy-build lease. The initial sandbox loopback
preflight returned `Operation not permitted` before any Runtime launch; the
approved local-bind rerun passed. This was a builder-sandbox result only.
All Cargo runs used these settings from the repository root:

```sh
export CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-013/tmp"
```

The first live command was:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime fixture_operator_ -- --nocapture --test-threads=1
```

It exited 0: `2 passed; 0 failed; 0 ignored`, 11.41 s in the test process
(12.37 s including Cargo). The harness-only baseline passed five tests and
the parser baseline passed one test before their mutations.

The exact test commands below each ran twice, planted then restored. The
mutation driver selected each record from `falsifiers.json`, required one
exact old-text match, and applied this byte operation in order:

```python
edit = item['edits'][0]
path = lane / edit['file']
original = path.read_bytes()
old, new = edit['old'].encode(), edit['new'].encode()
assert original.count(old) == 1
try:
    path.write_bytes(original.replace(old, new, 1))
    result = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=600)
    assert result.returncode == 101
    assert b'test result: FAILED. 0 passed; 1 failed;' in result.stdout
finally:
    path.write_bytes(original)
result = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=600)
assert result.returncode == 0
assert b'test result: ok. 1 passed; 0 failed;' in result.stdout
```

F-ac1k ran only the environment test. Its source was restored before any
further operator launch. F-ac1j changed only the API fixture host; Carrier
kept its loopback bind and fixed mDNS-off environment. Readiness requests
continued to use loopback. The operator stopped as soon as its census refused
the wildcard. These were the only fixture network calls.

**F-ac1j**

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime fixture_operator_sockets_are_loopback_only -- --exact --nocapture
```

Planted output:

```text
first operator socket census: "socket census refused TCP IPv4 non-loopback address"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 5.16s
```

Restored output:

```text
operator census: 2 then 2 loopback sockets, API listener present in both; samples at least 3 seconds apart; group stopped
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 7.88s
```

Cargo exit 101 planted (5.80 s), then exit 0 restored (8.34 s).

**F-ac1k**

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness launch_env_is_only_the_throwaway_home -- --exact --nocapture
```

Planted output:

```text
child environment must have exactly four entries
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.02s
```

Restored output:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.03s
```

Cargo exit 101 planted (0.77 s), then exit 0 restored (0.43 s).

**F-census-a**

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime socket_census_requires_parseable_loopback_endpoints_and_api_listener -- --exact --nocapture
```

Planted output:

```text
census must refuse incomplete or non-loopback evidence
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```

Restored output:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```

Cargo exit 101 planted (0.65 s), then exit 0 restored (0.35 s).

**F-managed-stop**

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness managed_child_stop_reaps_its_process_group -- --exact --nocapture
```

Planted output:

```text
SIGTERM must stop the parent and its child: "managed child or its group exceeded the 10 second stop bound"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 10.11s
```

Restored output:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.09s
```

Cargo exit 101 planted (10.78 s), then exit 0 restored (0.63 s).

**F-managed-drop**

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness managed_child_drop_kills_its_group_and_keeps_root -- --exact --nocapture
```

Planted output:

```text
assertion `left == right` failed
  left: Ok(())
 right: Err("keep the root after an unstopped child or failed stop")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.13s
```

Restored output:

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.11s
```

Cargo exit 101 planted (0.79 s), then exit 0 restored (0.52 s).

Every named test ran and failed under its mutation, then passed with the
original bytes restored. All 18 falsifier IDs are unique and all edit anchors
match exactly once. The five new falsifiers ran here; earlier falsifiers keep
their previous evidence, and their normal tests passed in this gate.

Native binary identities from the runs:

```text
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
```

Final lane gates:

| Command | Exit | Result | Elapsed |
| --- | --- | --- | --- |
| `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` | 0 | PASS | 0.07 s |
| `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` | 0 | 18 passed, 0 failed, 0 ignored | 43.90 s |
| `lab/agent-conformance/run.sh` | 0 | 18 PASS rows; binary hashes and both socket counts printed | 38.24 s |

The full table output was:

```text
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
operator census: 2 then 2 loopback sockets, API listener present in both; samples at least 3 seconds apart; group stopped
test | PASS/FAIL/BLOCKED (id)
fixture_operator_sockets_are_loopback_only | PASS
fixture_operator_starts_ready_and_stops_cleanly | PASS
foreign_and_wrong_version_imports_are_refused | PASS
home_is_throwaway | PASS
launch_env_is_only_the_throwaway_home | PASS
launch_stops_a_child_past_its_bound | PASS
managed_child_drop_kills_its_group_and_keeps_root | PASS
managed_child_stop_reaps_its_process_group | PASS
non_component_and_invalid_component_are_refused | PASS
probe_hash_is_stable | PASS
probe_imports_only_the_bus | PASS
probe_manifest_names_the_current_bus_world | PASS
run_table_requires_cargo_results | PASS
run_without_operator_is_refused_with_reason | PASS
runtime_data_dir_is_under_throwaway_home | PASS
serve_refuses_provider_whose_bytes_differ_from_its_hash | PASS
socket_census_requires_parseable_loopback_endpoints_and_api_listener | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
```

The repository's basic gate passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, 2 profiles, 28 method
contracts), `node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
`bash -n lab/agent-conformance/run.sh` also passed.

Gate runs preserved all lane source bytes and `git status --porcelain`.
The worktree began clean; only this task's candidate remains uncommitted.
The builder leaves Git mutations to the supervisor, so an empty status awaits
its commit. The cached upstream moved during this task: the final comparison
is 0 ahead / 10 behind, with an empty `git diff --stat HEAD..@{upstream} --
lab/agent-conformance`. Remote freshness and integration remain with the
supervisor; this builder made zero Git mutations or network calls. The supervisor owns the PR and can
copy the exact command/output blocks above into its review record.

The three retained failure roots were removed after review and an empty
`lsof -nP +D <root> -Fp` check for each. Passing roots removed themselves,
including the root-retention unit test after it verified that policy. A final
`pgrep -f` check of the lane's Runtime/provider executable paths returned exit
1 and empty output: zero suite processes remained. Existing earlier-task roots
were preserved. The local lifecycle inventory records the active candidate
and build/proof cleanup conditions for the supervisor rerun.

Principles check (paths relative to this lane):

| Question | Answer and evidence |
| --- | --- |
| 1. New name/URL in place of a code/content hash? | No. `tests/common/mod.rs:47` stamps the installed bytes' SHA-256; the API address in `tests/common/operator.rs:34` selects transport only. |
| 2. New ambient or UI authority? | No. `src/harness.rs:206` clears inherited environment and `src/harness.rs:210` fixes mDNS off; `fixtures/operator-config.toml:1` selects fixture admission only. |
| 3. A second operation path or rule copy? | No. `src/harness.rs:194` remains the sole spawn site, used by `launch`, `start` and process tools. |
| 4. Does the Runtime core grow? | No. `tests/common/operator.rs:18` reuses the existing Runtime build; all edits stay in this lane. |
| 5. Do refusals fail closed with a reason? | Yes. `tests/common/operator.rs:98` refuses census errors, `tests/common/operator.rs:227` requires API visibility, and `src/harness.rs:367` cleans up failed stops. |
| 6. Does capsule logic stay inside and trap down through grants? | Yes. `probe/src/lib.rs:8` retains the typed Bus bindings unchanged; this task adds fixture support only. |
| 7. Do tests and caught falsifiers prove the new rules? | Yes. `tests/runtime.rs:164`, `tests/runtime.rs:185`, `tests/runtime.rs:206`, `tests/harness.rs:82`, `tests/harness.rs:167` and `tests/harness.rs:182` passed; `falsifiers.json:214` onward owns the five planted failures recorded above. |


## 003 — ungranted read and network refusal (2026-10-26)

Added build-time read/network requests on the one probe source, shared artifact
builds and hash checks, live Bus-refusal tests through 013's operator fixture,
BLOCKED model/storage rows, and probe-only falsifiers.

`probe::request_effect` requests exactly one action and returns the Bus error
unchanged. The default `run_probe` keeps AC-002-ARGS. The repository build script
has no feature argument, so `tests/common/probe.rs::build_probe` passes the
Cargo feature cfg through inherited `RUSTFLAGS`: `--cfg feature="read"` or
`--cfg feature="network"`. It copies each build's bytes into memory before
removing the shared entrypoint and build directory. The effect tests install
those bytes in a SHA-256 directory inside the guarded throwaway root.
`tests/artifact.rs` accepts the five Bus v1 interfaces and checks two fresh
builds per selector, with distinct hashes across selectors.

The existing operator fixture owns startup, readiness, census and group stop.
`tests/effects.rs::assert_refusal` uses that fixture and the existing bounded
launch primitive. It checks a nonzero exit plus the exact lifecycle refusal
in stderr, then removes a passed Home. Failed assertions keep the root after
the operator has stopped. The guest stops after the capability request even
if a grant arrives; this deny-only task performs zero provider effects.
RT3 and AC-006-STORAGE have explicit ignored tests and BLOCKED table rows.

All build/test commands below held the repository's shared heavy-build lease.
Available space was 33.38 GiB before building, above the 12 GiB estimate plus
2 GiB reserve. Commands used the following environment, with build outputs
and temporary files inside this lane:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-003"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

The first effects run stopped at the sandbox's denied loopback bind, before
Runtime startup; it supplies zero live acceptance evidence. The permitted
local-bind rerun reached all three guest refusals and both socket samples.
Its assertions initially expected `Internal` / `Unavailable` without the
actual `BusError::` prefix. The corrected assertions require the full live
format; they retain the resource, lifecycle wrapper and nonzero-exit checks.
Operator captures and coordinates contents stayed unread.

Required lane gates after that correction:

| Command | Exit | Result | Elapsed |
| --- | --- | --- | --- |
| `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` | 0 | PASS | 0.11 s |
| `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` | 0 | 22 passed, 0 failed, 2 ignored (BLOCKED) | 159.91 s |

Both commands preserved `git status --porcelain`. The Home guard, cleared
environment, readiness and process-group checks passed. The repository basic
gate also passed: `git diff --check`, `node scripts/check-product-data.mjs`
(42 capsules, 2 profiles, 28 method contracts), `node --test
scripts/check-product-data.test.mjs` (99 passed), Runtime workspace formatting,
chain-provider formatting, and `bash -n lab/agent-conformance/run.sh`.

### F-ac1h — the read refusal must reach the harness

Applied the exact `F-ac1h` edit from `falsifiers.json` to `probe/src/lib.rs`,
ran the command, restored its original bytes, then ran the same command again:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects ungranted_effect_is_refused -- --exact --nocapture
```

Planted output:

```text
operator census: 2 then 2 loopback sockets for read; group stopped
probe refusal effect:read exit:Some(0) reason_present:false
expected nonzero exit and lifecycle refusal Internal("capsule manifest does not declare authority for localhost://Public/agent-conformance-ungranted/outside-fixture.txt"); exit:Some(0) reason_present:false
test ungranted_effect_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 23.43s
```

Restored output:

```text
operator census: 2 then 2 loopback sockets for read; group stopped
probe refusal effect:read exit:Some(1) reason_present:true
test ungranted_effect_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 22.72s
```

Planted: Cargo exit 101, 23.54 s.
Restored: Cargo exit 0, 22.81 s.

The planted test ran and failed because the guest returned success and the
reason disappeared. Restoring the probe returned exit 1 with the expected
reason. Both operator socket samples passed and both groups stopped. The
supervisor can copy these command/output blocks into the private PR.

### F-ac1n — the network refusal must reach the harness

Applied the exact probe edit from `falsifiers.json`, then restored the original
bytes before the second run. The command for both runs was:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects ungranted_network_is_refused -- --exact --nocapture
```

Planted (Cargo exit 101, 22.83 s):

```text
operator census: 2 then 2 loopback sockets for network; group stopped
probe refusal effect:network exit:Some(0) reason_present:false
expected nonzero exit and lifecycle refusal Internal("capsule manifest does not declare authority for elastos://net/stream"); exit:Some(0) reason_present:false
test ungranted_network_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 22.75s
```

Restored (Cargo exit 0, 22.00 s):

```text
operator census: 2 then 2 loopback sockets for network; group stopped
probe refusal effect:network exit:Some(1) reason_present:true
test ungranted_network_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 21.90s
```

### F-probe-exclusive — exact planted and restored checks

Applied its exact edit from `falsifiers.json`; restored the original source
bytes before the restored runs. Commands used the environment and lease above.

Planted (Cargo exit 101, 82.16 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact probe_effects_are_exclusive -- --exact --nocapture
```

```text
two effects must be refused
test probe_effects_are_exclusive ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 82.08s
```

Restored (Cargo exit 0, 91.11 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact probe_effects_are_exclusive -- --exact --nocapture
```

```text
test probe_effects_are_exclusive ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 91.02s
```

### F-probe-a — exact planted and restored checks

Applied its exact edit from `falsifiers.json`; restored the original source
bytes before the restored runs. Commands used the environment and lease above.

Planted (Cargo exit 101, 0.99 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance-probe tests::probe_refuses_without_a_launch_argument_channel -- --exact --nocapture
```

```text
assertion `left == right` failed
  left: Ok(())
 right: Err("probe launch arguments are unavailable in elastos:bus@v1")
test tests::probe_refuses_without_a_launch_argument_channel ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Planted (Cargo exit 101, 25.89 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects default_activation_refuses_without_selector -- --exact --nocapture
```

```text
probe refusal effect:default exit:Some(0) reason_present:false
expected nonzero exit and lifecycle refusal Unavailable("probe launch arguments are unavailable in elastos:bus@v1"); exit:Some(0) reason_present:false
test default_activation_refuses_without_selector ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 25.82s
```

Restored (Cargo exit 0, 0.49 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance-probe tests::probe_refuses_without_a_launch_argument_channel -- --exact --nocapture
```

```text
test tests::probe_refuses_without_a_launch_argument_channel ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Restored (Cargo exit 0, 26.76 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects default_activation_refuses_without_selector -- --exact --nocapture
```

```text
probe refusal effect:default exit:Some(1) reason_present:true
test default_activation_refuses_without_selector ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 26.69s
```

### F-probe-b — exact planted and restored checks

Applied its exact edit from `falsifiers.json`; restored the original source
bytes before the restored runs. Commands used the environment and lease above.

Planted (Cargo exit 101, 0.77 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact foreign_and_wrong_version_imports_are_refused -- --exact --nocapture
```

```text
assertion `left == right` failed
  left: Ok(())
 right: Err("probe import is outside the supported ElastOS Bus interfaces")
test foreign_and_wrong_version_imports_are_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```

Restored (Cargo exit 0, 1.33 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact foreign_and_wrong_version_imports_are_refused -- --exact --nocapture
```

```text
test foreign_and_wrong_version_imports_are_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```


### Principles check

Answers follow the task's question wording. Paths are relative to this lane.

| Question | Answer and evidence |
| --- | --- |
| 1. New name or URL in place of code/content hash? | No. `tests/effects.rs:20` computes SHA-256 from the component bytes and `:26` uses that hash for the local artifact directory; bundle-CID admission remains separate. |
| 2. New ambient access or UI authority? | No. `probe/src/lib.rs:51` calls the typed capability request; `:58` stops even on unexpected success. `tests/artifact.rs:53` permits only Bus v1 imports. |
| 3. A second operation path or rule copy? | No. `tests/common/probe.rs:33` is the shared probe builder. `tests/effects.rs:40` and `:44` reuse the existing operator and launch primitive. |
| 4. Does the trusted Runtime core grow? | No. All candidate paths stay under this lane; `tests/effects.rs:21` uses the existing Runtime-under-test helper. |
| 5. Do new refusals fail closed with a clear reason? | Yes. `probe/src/lib.rs:59` returns the Bus error unchanged; `tests/effects.rs:65` requires its exact lifecycle reason and a nonzero exit. |
| 6. Does capsule logic stay inside and call down through the Bus? | Yes. `probe/src/lib.rs:25` owns activation and `:51` requests authority through the generated typed Bus bindings. |
| 7. Do named tests and caught falsifiers prove each new rule? | Yes. `tests/effects.rs:82`, `:91`, `:100` and `tests/artifact.rs:157` cover refusal, default activation and exclusive selection; the planted/restored outputs above show F-ac1h, F-ac1n, F-probe-exclusive and both F-probe-a tests. |

These are author checks. Independent review, PR creation and the candidate
commit remain with the supervisor under this task's builder rules.

### F-probe-e — the moved builder retains its hash falsifier

Applied the unchanged mutation at its new `tests/common/probe.rs` path, then
restored the original bytes. Commands used the environment and lease above.

Planted (Cargo exit 101, 96.59 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact probe_hash_is_stable -- --exact --nocapture
```

```text
assertion `left == right` failed: independent Default builds differ
  left: "1c01fec4c1a0c901d7e72b68b7d190943e3178261c83ced381457ec73722fd49"
 right: "e79a40b7e49f493f904466b5d571bb0f01aaf2ce84b3d8f3bdd21cedd26cb870"
test probe_hash_is_stable ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 95.77s
```

Restored (Cargo exit 0, 96.10 s):

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact probe_hash_is_stable -- --exact --nocapture
```

```text
probe component sha256:1c01fec4c1a0c901d7e72b68b7d190943e3178261c83ced381457ec73722fd49 effect:default
probe component sha256:189abaef6b36b5fe4dac116cd8f24fc4971183c3505747e01c2f1a9c787da0fc effect:read
probe component sha256:9845b22b8dc0576e45cdf74effb9a790985cd778b36bf98d9c4a372ec9f8f6c5 effect:network
test probe_hash_is_stable ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 95.51s
```

All three new falsifiers and the three affected existing falsifiers were
caught. Every named test ran and failed while planted, then passed restored.
The other existing falsifiers retain their earlier evidence; all their normal
tests passed in this task’s full lane gate.

### Final table and cleanup

`lab/agent-conformance/run.sh` returned exit 0 in
160.44 s after all mutations were restored. Its output was:

```text
probe component sha256:1c01fec4c1a0c901d7e72b68b7d190943e3178261c83ced381457ec73722fd49 effect:default
probe component sha256:189abaef6b36b5fe4dac116cd8f24fc4971183c3505747e01c2f1a9c787da0fc effect:read
probe component sha256:9845b22b8dc0576e45cdf74effb9a790985cd778b36bf98d9c4a372ec9f8f6c5 effect:network
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
probe component sha256:1c01fec4c1a0c901d7e72b68b7d190943e3178261c83ced381457ec73722fd49 effect:default
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
operator census: 2 then 2 loopback sockets for default; group stopped
probe refusal effect:default exit:Some(1) reason_present:true
probe component sha256:189abaef6b36b5fe4dac116cd8f24fc4971183c3505747e01c2f1a9c787da0fc effect:read
operator census: 2 then 2 loopback sockets for read; group stopped
probe refusal effect:read exit:Some(1) reason_present:true
probe component sha256:9845b22b8dc0576e45cdf74effb9a790985cd778b36bf98d9c4a372ec9f8f6c5 effect:network
operator census: 2 then 2 loopback sockets for network; group stopped
probe refusal effect:network exit:Some(1) reason_present:true
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
operator census: 2 then 2 loopback sockets, API listener present in both; samples at least 3 seconds apart; group stopped
test | PASS/FAIL/BLOCKED (id)
default_activation_refuses_without_selector | PASS
fixture_operator_sockets_are_loopback_only | PASS
fixture_operator_starts_ready_and_stops_cleanly | PASS
foreign_and_wrong_version_imports_are_refused | PASS
home_is_throwaway | PASS
launch_env_is_only_the_throwaway_home | PASS
launch_stops_a_child_past_its_bound | PASS
managed_child_drop_kills_its_group_and_keeps_root | PASS
managed_child_stop_reaps_its_process_group | PASS
non_component_and_invalid_component_are_refused | PASS
operator_storage_is_under_throwaway_home | BLOCKED (AC-006-STORAGE)
probe_effects_are_exclusive | PASS
probe_hash_is_stable | PASS
probe_imports_only_the_bus | PASS
probe_manifest_names_the_current_bus_world | PASS
run_table_requires_cargo_results | PASS
run_without_operator_is_refused_with_reason | PASS
runtime_data_dir_is_under_throwaway_home | PASS
serve_refuses_provider_whose_bytes_differ_from_its_hash | PASS
socket_census_requires_parseable_loopback_endpoints_and_api_listener | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
ungranted_effect_is_refused | PASS
ungranted_model_call_is_refused | BLOCKED (RT3)
ungranted_network_is_refused | PASS
```

The table has 22 PASS rows and two BLOCKED rows. Every ignored test names its
blocker in GAPS.md. SHA-256 snapshots of all lane source files and
`git status --porcelain` matched before and after this run. The worktree began
clean and now contains only this task's uncommitted lane edits; an empty status
awaits the supervisor's commit, which this builder is instructed to leave to
the supervisor. The run itself added zero source changes.

All 21 falsifier IDs are unique and every edit anchor matches exactly once.
The nine retained task-003 failure roots were removed after each had an empty
`lsof -nP +D <root> -Fp` check. Passed roots removed themselves. The final
`pgrep -f` check for this lane's Runtime/provider paths returned exit 1 and
empty output. This task leaves zero fixture processes, test Homes or shared
probe entrypoints. Earlier roots retain their previous owners and cleanup
conditions. The private lifecycle inventory keeps the active branch/worktree
and build artifacts for the supervisor rerun, with removal after acceptance
and evidence transfer.

The cached upstream advanced during this task: 0 ahead / 9 behind.
`git diff --stat HEAD..@{upstream} -- lab/agent-conformance` is empty. Remote
freshness and integration remain with the supervisor; the checks used the
documented loopback fixture and the builder changed no Git state. Candidate source and all test changes
stay under `lab/agent-conformance/`.


## 005 — parallel clients and bounded runaway (2026-10-26)

Extended the one spawn primitive with `RunningInstances::start/collect`, added
build-time finite-task and runaway variants to the one probe, and added
process-isolation rows with separate blocked capsule/result/reason claims.

Plan: read 003/006/013's code and notes, extend managed collection, exercise
four clients against one operator, then run the lane gates and planted/restored
falsifiers. The supplied backlog/spec were the read-only task context; this
checkout has neither the external queue nor a humanizer skill under the
permitted repository scope. All edits remain in this lane. Git state changes,
network fetches, Runtime changes and provider changes stay with their owners.

The local volume had 33.74 GiB free before builds, above the 12 GiB estimate
plus 2 GiB reserve. Each Cargo gate held the existing repository heavy-build
lease through `fcntl.flock` on its read-only descriptor. Commands used:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

The first live attempt failed at the sandbox loopback bind before Runtime
started (83.20 s test time); it supplies zero Runtime evidence. The same test
with local process/socket access ran four clients against one operator. The
parallel finite row passed with elapsed times 0.063, 0.088, 0.116 and 0.131 s.
Each client returned only its own computed diagnostic. Both operator socket
samples counted two loopback sockets and the group stopped.

The initial strict runaway check returned exit 1 naturally after 0.053 s.
Its lifecycle-trap context was present; the fuel-exhaustion cause was absent.
The strict assertion failed. It remains intact in the ignored
`process_isolation::runaway_is_stopped_with_reason` test under AC-005-REASON.
The separate live row `runaway_trap_is_bounded_while_siblings_finish` grades
only bounded natural trapping and sibling diagnostics. RT4 and AC-002-ARGS
also have explicit ignored tests; their claims stay outside the PASS count.

F-ac3a uses the planner's allowed probe mutation: Runtime fuel/memory limits
are compile-time constants with no fixture control. Its finite-loop mutation
checks only the live bounded-trap half. The full stop-with-reason acceptance
remains blocked until Runtime preserves the cause on stderr.

The repository basic gate passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, 2 profiles, 28 method
contracts), `node --test scripts/check-product-data.test.mjs` (99 passed),
Runtime workspace formatting, chain-provider formatting, and
`bash -n lab/agent-conformance/run.sh`. The lane formatting gate also passed.

### F-parallel-capture — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_collection_preserves_each_status_and_capture -- --exact --nocapture
```

planted: exit 101, 0.83 s.

```text
running 1 test
assertion `left == right` failed
  left: [111, 117, 116, 48]
 right: [101, 114, 114, 48]
test parallel_collection_preserves_each_status_and_capture ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.13s
```

restored: exit 0, 0.58 s.

```text
running 1 test
test parallel_collection_preserves_each_status_and_capture ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.13s
```

### F-parallel-bound — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_timeout_is_failure_and_reaps_every_group -- --exact --nocapture
```

planted: exit 101, 3.81 s.

```text
running 1 test
assertion `left == right` failed
  left: Ok(())
 right: Err("keep the root after an unstopped child or failed stop")
test parallel_timeout_is_failure_and_reaps_every_group ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 3.11s
```

restored: exit 0, 1.59 s.

```text
running 1 test
test parallel_timeout_is_failure_and_reaps_every_group ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 1.13s
```

### F-parallel-operator-guard — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_attach_uses_only_guarded_fixture_coordinates -- --exact --nocapture
```

planted: exit 101, 0.78 s.

```text
running 1 test
assertion `left == right` failed
  left: None
 right: Some("temp directory must use directories without symlinks")
test parallel_attach_uses_only_guarded_fixture_coordinates ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.08s
```

restored: exit 0, 0.5 s.

```text
running 1 test
test parallel_attach_uses_only_guarded_fixture_coordinates ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.04s
```

### F-parallel-coordinates — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_attach_uses_only_guarded_fixture_coordinates -- --exact --nocapture
```

planted: exit 101, 0.74 s.

```text
running 1 test
required fixture environment entry is missing
test parallel_attach_uses_only_guarded_fixture_coordinates ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.05s
```

restored: exit 0, 0.5 s.

```text
running 1 test
test parallel_attach_uses_only_guarded_fixture_coordinates ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.04s
```

### F-parallel-start — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_collection_preserves_each_status_and_capture -- --exact --nocapture
```

planted: exit 101, 2.74 s.

```text
running 1 test
all children must start before any collection
test parallel_collection_preserves_each_status_and_capture ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.05s
```

restored: exit 0, 0.56 s.

```text
running 1 test
test parallel_collection_preserves_each_status_and_capture ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.11s
```

### F-parallel-drain — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test harness parallel_collection_refuses_live_descendants -- --exact --nocapture
```

planted: exit 101, 0.79 s.

```text
running 1 test
assertion `left == right` failed
  left: None
 right: Some("completed child left a live process group")
test parallel_collection_refuses_live_descendants ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.09s
```

restored: exit 0, 0.57 s.

```text
running 1 test
test parallel_collection_refuses_live_descendants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.11s
```

### F-probe-exclusive — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test artifact probe_effects_are_exclusive -- --exact --nocapture
```

planted: exit 101, 0.75 s.

```text
running 1 test
two effects must be refused
test probe_effects_are_exclusive ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.05s
```

restored: exit 0, 0.31 s.

```text
running 1 test
test probe_effects_are_exclusive ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.27s
```

### F-ac3a — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects -- --exact --nocapture process_isolation::runaway_trap_is_bounded_while_siblings_finish
```

planted: exit 101, 79.16 s.

```text
running 1 test
test process_isolation::runaway_trap_is_bounded_while_siblings_finish has been running for over 60 seconds
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: runaway exit:Some(0) fuel_reason:false elapsed:0.051s
assertion `left == right` failed: Runtime must report a failure, not a signal
  left: Some(0)
 right: Some(1)
test process_isolation::runaway_trap_is_bounded_while_siblings_finish ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 78.50s
```

restored: exit 0, 78.11 s.

```text
running 1 test
test process_isolation::runaway_trap_is_bounded_while_siblings_finish has been running for over 60 seconds
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: runaway exit:Some(1) fuel_reason:false elapsed:0.073s
parallel process isolation: task:1 exit:Some(1) own_result:true elapsed:0.104s
parallel process isolation: task:2 exit:Some(1) own_result:true elapsed:0.119s
parallel process isolation: task:3 exit:Some(1) own_result:true elapsed:0.146s
test process_isolation::runaway_trap_is_bounded_while_siblings_finish ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 78.04s
```

### F-parallel-result — planted and restored

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects -- --exact --nocapture process_isolation::parallel_instances_complete_independently process_isolation::runaway_trap_is_bounded_while_siblings_finish
```

planted: exit 101, 84.79 s.

```text
running 2 tests
test process_isolation::parallel_instances_complete_independently has been running for over 60 seconds
test process_isolation::runaway_trap_is_bounded_while_siblings_finish has been running for over 60 seconds
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: task:0 exit:Some(1) own_result:true elapsed:0.064s
parallel process isolation: task:1 exit:Some(1) own_result:false elapsed:0.080s
expected exactly this task's computed diagnostic
test process_isolation::parallel_instances_complete_independently ... FAILED
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: runaway exit:Some(1) fuel_reason:false elapsed:0.063s
parallel process isolation: task:1 exit:Some(1) own_result:false elapsed:0.078s
expected exactly this task's computed diagnostic
test process_isolation::runaway_trap_is_bounded_while_siblings_finish ... FAILED
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 8 filtered out; finished in 84.72s
```

restored: exit 0, 82.96 s.

```text
running 2 tests
test process_isolation::parallel_instances_complete_independently has been running for over 60 seconds
test process_isolation::runaway_trap_is_bounded_while_siblings_finish has been running for over 60 seconds
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: task:0 exit:Some(1) own_result:true elapsed:0.050s
parallel process isolation: task:1 exit:Some(1) own_result:true elapsed:0.065s
parallel process isolation: task:2 exit:Some(1) own_result:true elapsed:0.091s
parallel process isolation: task:3 exit:Some(1) own_result:true elapsed:0.106s
test process_isolation::parallel_instances_complete_independently ... ok
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: runaway exit:Some(1) fuel_reason:false elapsed:0.058s
parallel process isolation: task:1 exit:Some(1) own_result:true elapsed:0.086s
parallel process isolation: task:2 exit:Some(1) own_result:true elapsed:0.101s
parallel process isolation: task:3 exit:Some(1) own_result:true elapsed:0.117s
test process_isolation::runaway_trap_is_bounded_while_siblings_finish ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 82.91s
```


All eight new falsifiers and the updated F-probe-exclusive were caught.
Every named test failed while planted and passed after byte-for-byte
restoration. F-parallel-result names two tests; both failed and both passed
restored. These are author checks. The supervisor owns independent review,
commit and integration.

### Principles check

Answers follow the task's question wording; paths are relative to this lane.

| Question | Answer and evidence |
| --- | --- |
| 1. New name or URL in place of code/content hash? | No. `tests/effects.rs:32` computes SHA-256 and stages those bytes under that hash; task labels identify fixture computations. Bundle-CID acceptance stays separate. |
| 2. New ambient capsule access or UI authority? | No. `probe/src/lib.rs:58` and `:78` only compute inside the capsule. The artifact gate checks all eight variants against the existing Bus import allowlist. |
| 3. A second operation path or copy of a rule? | No. `src/harness.rs:464` calls the one spawn site; `tests/effects.rs:32` stages both old and new probe effects. |
| 4. Does the trusted Runtime core grow? | No. `tests/common/parallel.rs:68` uses the existing CLI; every candidate path is under this lane. |
| 5. Do new refusals fail closed with clear reasons? | Yes. `src/harness.rs:366` refuses a surviving process group and `:486` reports the shared deadline. The existing Runtime stop-cause gap stays BLOCKED in `tests/common/parallel.rs:162`. |
| 6. Does the capsule keep its logic inside and use the Bus for granted effects? | Yes. `probe/src/lib.rs:58` and `:78` keep finite and runaway computation inside; the existing typed capability path remains at `:85`. |
| 7. Do tests and caught falsifiers prove the new live rules? | Yes. `tests/common/parallel.rs:151` and `:156`, plus the four parallel harness tests, have the planted/restored evidence above. The three new blocked claims receive zero passing credit. |

The first full lane gate returned exit 0 in 411.16 s with 27 passed and five
ignored (BLOCKED). The new descendant-cleanup regression was then verified
with the other three parallel harness checks (four passed). The final report
run below covers the complete restored candidate, including that regression.
The cached upstream moved to 0 ahead / 12 behind during the task; its lane diff
was empty. Integration stays with the supervisor; this builder changed no Git
state and made no network fetch.


The first final-report attempt stopped before building because another local
operator held the shared heavy-build lease. Ten already-recorded task failure
Homes had been removed after an empty open-file census. Automatic approval
review then refused a proposed cleanup of unrecorded Homes because ownership
was unproven. The safer disposition preserves those 29 roots under an explicit
supervisor ownership/evidence-review condition in the ignored local inventory.
Their contents stay unread. Cleanup is therefore deferred, not reported complete.

### Final report run

`lab/agent-conformance/run.sh` returned exit 0 in 458.94 s.
All lane source SHA-256 values and `git status --porcelain` matched before
and after the run. The candidate remains uncommitted under the builder rules.

```text
probe component sha256:36ad857b48bdffdfe8fd86ac7fbfd3420861568abd91ec0060933af3debb4ea2 effect:default
probe component sha256:0ae8a9ff8403d03f0145f518174df50f563f76935f508feedeb77cda061e6118 effect:read
probe component sha256:6b251623dc4ae200abe4a32ee95e904627a373cea23a488d36995d3154cd1e88 effect:network
probe component sha256:15ec756b4f4e6189bb213fd6845c5ce0f365732f56c19d8e6d48e4d57b794040 effect:task-a
probe component sha256:2ca200baec1edb2a641ba662469d68ded90041e5d5a5a9627f116abecd78ee2f effect:task-b
probe component sha256:2b9f2fc4c38f498dd33c7a219372a837e863a3c48fb6afd9b7becfb42096a8d8 effect:task-c
probe component sha256:11b6e18fd2229353d66c3b0c4d9e2930838558a827f5598c5fa6156d8d1a4878 effect:task-d
probe component sha256:e8c23692783e8064244b9e6abb54930196cdc10d52923c48b75fa8ccac69cb1b effect:runaway
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
probe component sha256:15ec756b4f4e6189bb213fd6845c5ce0f365732f56c19d8e6d48e4d57b794040 effect:task-a
probe component sha256:2ca200baec1edb2a641ba662469d68ded90041e5d5a5a9627f116abecd78ee2f effect:task-b
probe component sha256:2b9f2fc4c38f498dd33c7a219372a837e863a3c48fb6afd9b7becfb42096a8d8 effect:task-c
probe component sha256:11b6e18fd2229353d66c3b0c4d9e2930838558a827f5598c5fa6156d8d1a4878 effect:task-d
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: task:0 exit:Some(1) own_result:true elapsed:0.088s
parallel process isolation: task:1 exit:Some(1) own_result:true elapsed:0.119s
parallel process isolation: task:2 exit:Some(1) own_result:true elapsed:0.146s
parallel process isolation: task:3 exit:Some(1) own_result:true elapsed:0.182s
probe component sha256:36ad857b48bdffdfe8fd86ac7fbfd3420861568abd91ec0060933af3debb4ea2 effect:default
operator census: 2 then 2 loopback sockets for default; group stopped
probe refusal effect:default exit:Some(1) reason_present:true
probe component sha256:e8c23692783e8064244b9e6abb54930196cdc10d52923c48b75fa8ccac69cb1b effect:runaway
probe component sha256:2ca200baec1edb2a641ba662469d68ded90041e5d5a5a9627f116abecd78ee2f effect:task-b
probe component sha256:2b9f2fc4c38f498dd33c7a219372a837e863a3c48fb6afd9b7becfb42096a8d8 effect:task-c
probe component sha256:11b6e18fd2229353d66c3b0c4d9e2930838558a827f5598c5fa6156d8d1a4878 effect:task-d
operator census: 2 then 2 loopback sockets; four clients, one operator; group stopped
parallel process isolation: runaway exit:Some(1) fuel_reason:false elapsed:0.076s
parallel process isolation: task:1 exit:Some(1) own_result:true elapsed:0.105s
parallel process isolation: task:2 exit:Some(1) own_result:true elapsed:0.130s
parallel process isolation: task:3 exit:Some(1) own_result:true elapsed:0.167s
probe component sha256:0ae8a9ff8403d03f0145f518174df50f563f76935f508feedeb77cda061e6118 effect:read
operator census: 2 then 2 loopback sockets for read; group stopped
probe refusal effect:read exit:Some(1) reason_present:true
probe component sha256:6b251623dc4ae200abe4a32ee95e904627a373cea23a488d36995d3154cd1e88 effect:network
operator census: 2 then 2 loopback sockets for network; group stopped
probe refusal effect:network exit:Some(1) reason_present:true
elastos sha256:150bc7279ca22856b8464cc61d3f52aa33385fc7fd081c939138706c181d7efd
localhost-provider sha256:f70baa44037dea2c97167324864d8a35d7eb0845854d2023bf41f426681451e2
operator census: 2 then 2 loopback sockets, API listener present in both; samples at least 3 seconds apart; group stopped
process_isolation rows: process isolation, not capsule isolation; diagnostic results only
test | PASS/FAIL/BLOCKED (id)
default_activation_refuses_without_selector | PASS
fixture_operator_sockets_are_loopback_only | PASS
fixture_operator_starts_ready_and_stops_cleanly | PASS
foreign_and_wrong_version_imports_are_refused | PASS
home_is_throwaway | PASS
launch_env_is_only_the_throwaway_home | PASS
launch_stops_a_child_past_its_bound | PASS
managed_child_drop_kills_its_group_and_keeps_root | PASS
managed_child_stop_reaps_its_process_group | PASS
non_component_and_invalid_component_are_refused | PASS
operator_storage_is_under_throwaway_home | BLOCKED (AC-006-STORAGE)
parallel_attach_uses_only_guarded_fixture_coordinates | PASS
parallel_capsules_complete_independently | BLOCKED (RT4)
parallel_collection_preserves_each_status_and_capture | PASS
parallel_collection_refuses_live_descendants | PASS
parallel_instances_return_success_payloads | BLOCKED (AC-002-ARGS)
parallel_timeout_is_failure_and_reaps_every_group | PASS
probe_effects_are_exclusive | PASS
probe_hash_is_stable | PASS
probe_imports_only_the_bus | PASS
probe_manifest_names_the_current_bus_world | PASS
process_isolation::parallel_instances_complete_independently | PASS
process_isolation::runaway_is_stopped_with_reason | BLOCKED (AC-005-REASON)
process_isolation::runaway_trap_is_bounded_while_siblings_finish | PASS
run_table_requires_cargo_results | PASS
run_without_operator_is_refused_with_reason | PASS
runtime_data_dir_is_under_throwaway_home | PASS
serve_refuses_provider_whose_bytes_differ_from_its_hash | PASS
socket_census_requires_parseable_loopback_endpoints_and_api_listener | PASS
tests::probe_refuses_without_a_launch_argument_channel | PASS
ungranted_effect_is_refused | PASS
ungranted_model_call_is_refused | BLOCKED (RT3)
ungranted_network_is_refused | PASS
```


Final count: 28 PASS, five BLOCKED, zero FAIL. The four finite diagnostics
completed within 0.182 s; the runaway trapped naturally after 0.076 s and its
three siblings completed within 0.167 s in this run. These times exclude
probe preparation and include client launch, polling and group checks.
The Runtime stop-cause row remains BLOCKED.

Final read-only checks found zero matching Runtime or fixture-provider
processes under this lane's test paths, zero shared probe WASM entrypoints,
and exactly 15 candidate paths, all inside the lane. Every falsifier anchor
matched once after restoration. The local inventory was refreshed; the 29
unconfirmed retained Homes keep their ownership-review condition. Earlier
owners retain their recorded roots. Git state was left to the supervisor.
At handoff the cached upstream was 0 ahead / 28 behind, with an empty lane
diff against that upstream. Final `git diff --check` passed. Source changes
are ready for independent review; the blocked claims and deferred cleanup
remain explicit.

## 018 — one version receipt through the existing report (2026-10-26)

Added a retained `VERSIONS.json` to the existing report command, with native
hashes, complete probe bundle lab CIDs, Git identity, and the matching graded
table; all source changes stay in `lab/agent-conformance/`.

Read the supplied Mission, task and BACKLOG item 16, the report/build/staging
code, the sibling identity API and README, and this lane's README, RUNBOOK,
GAPS and 003/005 handoff notes before editing. The checkout has neither the
external MISSION/INBOX files nor a humanizer skill in the permitted repository
scope. The supplied latest inbox order is the task context. The plan was to
extend the one evidence parser, share staging identity, exercise synthetic
refusals and mutations, then run both lane gates and the live report command.

`src/identity.rs::stage_probe` extends the existing guarded staging path. It
calls `capsule_identity::checked_bundle` over the exact manifest and payload,
then hashes the component from the returned checked entries. The sibling
crate owns manifest validation, walking and bundle encoding. The lane consumes
its read-only path dependency; existing dependency versions stay fixed in the
lane lockfile. The already-locked serde/serde_json/sha2 libraries supply typed
observations and serialization. Native hashes still come from the existing
Runtime/provider build helpers and `sha256_file`.

`Observation` supplies one format for native, build-only and launched records.
`probe_hash_is_stable` emits build-only bundle identities. The live effect and
parallel tests emit launched identities after their existing launch primitive
starts or returns. The report keeps the two categories separate, checks the
required variants for each active journey, deduplicates identical records and
refuses conflicting role/effect identities.

`src/report.rs::write_run` parses the same evidence once for the table and
receipt. `GitIdentity::read` queries the current full commit and dirty state
with optional Git locks disabled. The receipt stores explicit identity fields,
coverage failures, suite outcome, combined command outcome, and the graded table
with its SHA-256. Its typed inputs exclude child captures, HTTP bodies and
environment dumps. Exclusive creation preserves a prior receipt and symlink
target; any write error fails A14 and the command with a named reason.
`run.sh` builds the current report first, reports Cargo listing/test failures
through it, and retains the small receipt on success. RUNBOOK records removal
after review and the existing failed-run retention rule. The lab CID label
stays `lab-cid:sha256:...`; Runtime CID launch and the existing blockers retain
their separate acceptance gates. Task 019's SKIPPED grading is absent on this
base; the existing grader is preserved.

### Named checks and measured results

The three new tests are `versions_receipt_binds_current_run`,
`versions_receipt_rejects_incomplete_identity`, and
`versions_receipt_uses_the_staged_bundle_identity`. The first checks two
synthetic run receipts against their own native/probe/Git identities, including
both dirty states, then exercises the actual report CLI and its Git query.
The second checks missing, malformed, conflicting and omitted live identities,
build-only substitution, failed Git queries, exclusive creation, symlinks and
write failure with exact reasons. The third uses the existing identity library
as its oracle: a manifest-only byte change alters the receipt's bundle field
while the component hash stays the same. These fixtures supply zero live proof.
`run_table_requires_cargo_results` also checks the combined command result while
preserving Cargo FAIL and BLOCKED rows.

All Cargo commands held the existing shared heavy-build lease through an
exclusive `fcntl.flock` on its read-only descriptor. Initial free space was
29.16 GiB; the full locked gate began with 28.90 GiB and the final report run
with 28.87 GiB, each above the 12 GiB estimate plus 2 GiB reserve. Commands from
the repository root used:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-018"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

`run.sh` sets its own TMPDIR to its fresh run directory. Formatting passed in
0.19 s. The locked full suite returned exit 0 in 378.16 s: 31 passed, zero
failed, five ignored with their existing blocker IDs. Artifact tests took
226.00 s and live effect tests took 136.54 s. The earlier sandbox prerequisite
command, `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
--test runtime fixture_operator_starts_ready_and_stops_cleanly -- --exact`,
returned exit 101 in 1.77 s at its loopback bind with `Operation not permitted`,
before Runtime startup. It supplies zero Runtime evidence. The full gate with
local process/socket access passed the operator readiness and cleanup checks.

The basic repository gate also passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, two profiles, 28 method
contracts), `node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`,
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`, and
`bash -n lab/agent-conformance/run.sh`.

### Falsifiers, planted and restored

Both entries use `command: lab` in the existing `falsifiers.json`. Mutations
changed only `src/report.rs`, ran only synthetic receipt tests, and restored
the original bytes in a `finally` block. Each entry names one test; that test
ran and failed under the mutation, then passed after restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml \
  --test report versions_receipt_rejects_incomplete_identity -- --exact --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml \
  --test report versions_receipt_uses_the_staged_bundle_identity -- --exact --nocapture
```

| Falsifier | Planted result | Restored result |
| --- | --- | --- |
| F-versions-required | Exit 101, one failed, 0.83 s; caught acceptance of a missing Runtime SHA-256 | Exit 0, one passed, 0.72 s |
| F-versions-bundle | Exit 101, one failed, 0.86 s; receipt bundle field differed from the identity library's lab CID | Exit 0, one passed, 0.60 s |

The two synthetic failure roots and the sandbox pre-launch root were reviewed,
checked with an empty open-file census, and removed. Their contents remained
unread. The ignored lifecycle inventory records the task worktree, branch,
proof outputs and cleanup conditions. Existing unrelated roots remain with
their owners. The supervisor owns commits, independent review and integration.

### Principles check

Answers use the task's question wording; paths are relative to this lane.

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name/URL in place of a code/content hash? | No | `src/identity.rs:71` records the component SHA-256 and complete bundle lab CID; effect labels describe fixtures. |
| 2. New ambient capsule or UI authority? | No | `tests/effects.rs:47` retains the existing guarded Runtime launch; this task changes host evidence only. |
| 3. A second path or copy of an operation rule? | No | `src/identity.rs:62` calls the sibling identity API; `src/report.rs:279` uses the one evidence parser and grader for both outputs. |
| 4. Does the Runtime core grow? | No | `Cargo.toml:14` consumes the lab identity dependency; every edited source path is inside this lane. |
| 5. Do new refusals fail closed with a clear reason? | Yes | `src/report.rs:90` checks required identities, and `src/report.rs:342` uses exclusive receipt creation with named write errors. |
| 6. Does the capsule keep its logic and granted Bus calls? | Yes | `tests/artifact.rs:88` retains the Bus import checks; the probe source and grants stay unchanged. |
| 7. Do named tests and caught falsifiers prove the rules? | Yes | `tests/report.rs:224` and `tests/report.rs:420` have the planted/restored failures recorded above. |
| 8. Are identity, admission and allowance separate decisions? | Yes | `src/identity.rs:49` defines the lab CID as identity; the receipt preserves each journey's grade in `src/report.rs:297`. |

### Final report run and retained evidence

`lab/agent-conformance/run.sh` returned exit 0 in 363.69 s. The table contains
31 passing Cargo tests, five unchanged BLOCKED rows, and a separate A14 PASS.
The lane's Rust sources, test sources, Cargo manifest/lockfile, run script and
falsifier list had identical SHA-256 values before and after this run.

The tested receipt is
[`target/run-table.oA5fNx/VERSIONS.json`](target/run-table.oA5fNx/VERSIONS.json).
It is the only file retained in that run directory and is 6,531 bytes.
Inspection checked all of the following against the actual run:

- `identity_status` is `complete`; `command_success` is true; the suite outcome
  stays `BLOCKED` because its five open acceptance claims retain their grades.
- Both native SHA-256 values match the built binary bytes in `target/runtime`.
- All eight launched variants have component hashes and complete bundle lab
  CIDs; each agrees with its build-only observation.
- The receipt's full repository commit equals the current HEAD, and `dirty`
  is true for these uncommitted task edits.
- The embedded table equals the printed table byte for byte, and its SHA-256
  matches that table. The missing/invalid identity list is empty.

The final metadata check found zero retained Homes created by this task's
runs. The ignored local inventory keeps the receipt and command outputs until
task 018 review, then calls for removal. Branch/worktree inventory was rerun;
the task stays on its original branch and worktree, with changes confined to
this lane. The cached upstream divergence is zero ahead and zero behind.
Network access and Git-state changes were outside this builder's work. Other
worktrees and refs remain under their existing owners. These are author
checks; the supervisor owns independent review and integration.
