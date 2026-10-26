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
after review and the existing failed-run retention rule. The identity library
owns the lab CID label; Runtime CID launch and the existing blockers retain
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


## 018 follow-up — explicit receipt authority boundary (2026-10-26)

The starting checkout already contains the receipt writer, staging identities,
three receipt tests and the two required falsifiers from task 018. This follow-up
keeps that implementation and adds the missing authority description to
`src/report.rs::write_run`. Each receipt now states that a lab CID and a separate
signed record give zero admission or permission credit. Runtime decides admission;
resource authority requires its grant for the requesting session. Only the
corresponding observed Runtime journey supplies that evidence. RUNBOOK gives the
same ownership rule and retains the existing review-and-remove policy.

`versions_receipt_binds_current_run` now checks the serialized description in
both synthetic runs. New F-versions-boundary removes that field and fails this
named test. F-versions-required and F-versions-bundle retain their existing edits
and named tests. All mutations stayed in `src/report.rs`, used synthetic inputs,
and restored the exact source bytes in a `finally` block.

All build commands held the existing shared `fcntl.flock` lease. Free space was
28.18 GiB before the focused checks, above the 12 GiB estimate plus 2 GiB reserve.
Commands ran from the repository root with:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-018-followup"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report versions_receipt_rejects_incomplete_identity -- --exact --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report versions_receipt_uses_the_staged_bundle_identity -- --exact --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report versions_receipt_binds_current_run -- --exact --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

Each single-test command ran once planted and once restored. The focused report
suite passed all four tests in 2.12 s. The initial format check passed in 0.08 s.

| Falsifier | Planted | Restored |
| --- | --- | --- |
| F-versions-required | Exit 101; named test failed; 0.86 s | Exit 0; named test passed; 0.72 s |
| F-versions-bundle | Exit 101; named test failed; 0.87 s | Exit 0; named test passed; 0.65 s |
| F-versions-boundary | Exit 101; named test failed; 1.31 s | Exit 0; named test passed; 0.88 s |

The basic gate passed: `git diff --check`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`,
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`, and
`bash -n lab/agent-conformance/run.sh`.

### Principles check for this follow-up

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New names or URLs in place of code/content hashes? | No | `src/identity.rs:73` retains separate component SHA-256 and bundle lab CID fields. |
| 2. New capsule or UI ambient authority? | No | `src/report.rs:308` describes evidence; the change leaves Runtime grants and the probe unchanged. |
| 3. A second path or copy of an operation rule? | No | `src/report.rs:279` retains the shared evidence parser; `src/identity.rs:62` calls the existing bundle library. |
| 4. Does the Runtime core grow? | No | `src/report.rs:308` adds a host-side receipt field within this lane. |
| 5. Do new refusals fail closed with a clear reason? | Yes | `src/report.rs:91` and `src/report.rs:339` retain the tested identity and exclusive-write refusals. |
| 6. Does the capsule keep its logic and granted Bus calls? | Yes | `tests/artifact.rs:88` retains the Bus import test; probe source stays unchanged. |
| 7. Do named tests and caught falsifiers prove the rules? | Yes | `tests/report.rs:135` checks the added field; F-versions-boundary failed planted and passed restored. |
| 8. Are identity, admission and allowance separate decisions? | Yes | `src/report.rs:308` records Runtime admission and the requesting session's resource grant as separate requirements. |

### Fresh full gates and receipt inspection

With local process/socket access for the isolated fixtures, the final formatting
check passed in 0.13 s. The locked lane suite returned exit 0 in 406.62 s:
31 passed, zero failed, five ignored with their existing blocker IDs. The
artifact group took 233.49 s and the live effect group took 157.51 s. Free space
was 28.17 GiB at gate start.

`lab/agent-conformance/run.sh` returned exit 0 in 423.70 s, starting with
27.62 GiB free. The matching table has 31 passing Cargo tests, five BLOCKED rows
and A14 PASS. Its receipt is
[`target/run-table.sX45vx/VERSIONS.json`](target/run-table.sX45vx/VERSIONS.json),
6,823 bytes and the sole file retained in that fresh run directory.

Inspection matched the embedded table byte for byte to stdout and checked its
SHA-256. Both native hashes match `target/runtime/debug/elastos` and
`target/runtime/debug/localhost-provider`. All eight launched identities match
this invocation's typed observations and its separate build-only records.
The receipt records the current full repository commit and `dirty: true`;
`identity_status` is `complete`, `command_success` is true, and `suite_outcome`
stays `BLOCKED`. Its authority description is present. These are version and
journey results for the lab fixture, with the existing admission and grant
boundaries retained.

The normal gates created zero retained Homes. A final read-only process census
found zero matching lane Runtime/provider processes. Three expected synthetic
falsifier failure roots remain for supervisor review, with their removal
condition in the ignored lifecycle inventory. The receipt and command outputs
also remain until that review. All lane code, manifests, scripts and falsifiers
had identical SHA-256 values before and after the full gates.

The final branch/worktree inventory covers the existing task checkout, with
cached upstream divergence zero ahead / zero behind. Network access remains
disabled, so this is cached-ref evidence. The builder made source edits only
inside this lane and left Git history and refs unchanged. The supervisor owns
independent review, commits and integration.


## 019 — grant integration, bounded preparation and memory-only credentials (2026-10-26)

Carried 015's fixture grant controller onto the current base, preserved 005's
collector and 018's receipt, and added bounded probe preparation and the named
attach-secret check. All edits stay in this lane; the supervisor owns Git state.

Read the supplied Mission, BACKLOG item 12, integration note and 10:40 admission
clarification, then the current lane implementation and handoff records. The
external Mission/inbox/review files are outside builder scope. The repository
has no humanizer skill; this entry uses direct statements of behavior and ownership.
Read 015's author delta from `cb2ff327f27a3e12a5cac30cce4971905c57adcc` to
`91cb1a3296bafc551a7bda350a4d34d50a816a60` and compared the integrated
`2e304d1d6611750cea62dade95a3db051d892309` candidate. The supplied Claude PASS
belongs to that earlier author candidate. This change requires fresh independent
review. The earlier timeout remains a complete-gate timeout, without an inferred
hung test.

`Controller` and `Fixture` retain exact resource/action/reason matching,
ambiguity refusal, fixture-selected duration and production loopback approval.
The probe retains its narrow manifest bound and guest byte comparison.
`RunningInstances::collect_with` extends the existing collector and spawn site.
`Operator::begin_check` / `finish_check` share readiness, both census samples and
group stop across effects, parallel checks and the census test. Both refusal
journeys use `assert_output_refusal`. Package identity and admission supply zero
fixture grants; Runtime owns each permission decision.

`build_probe` now cleans only the probe package in each selector's WASM release
cache, then uses the existing repository component script. It requires a fresh
probe compilation on every call. Dependencies and the componentizer are reused;
all ten variants still have two actual compilations, both import checks, stable
pair hashes and distinct variant hashes. Selector exclusivity remains intact.

`attach_secret_stays_in_memory` first checks synthetic in-memory canaries on
stdout, stderr, report, receipt, committed source and candidate source surfaces,
then exercises both real fixture journeys. Every granted/sibling journey uses
the same credential checker for its actual attach secret and returned tokens.
The spawn site supplies the complete expected capture inventory; empty or missing
evidence fails. Git lists only lane source files. Runtime owns its coordinates
input; harness credential copies remain in memory. `render_run` is extracted
from the existing writer so both the report and receipt are checked before a
file write. The existing writer consumes those same serialized bytes.

The carried report test preserves SKIPPED for pre-probe setup failure and FAIL
for an `ok` result beside SKIPPED, Runtime failures and failed assertions.
`skipped_report_keeps_a_nonzero_exit` also exercises the real report CLI and its
receipt. Safe prerequisite causes are retained, including the OS bind refusal.
The five existing BLOCKED rows retain their acceptance boundaries in GAPS.md.

### Author checks and cache conditions

Commands ran from the repository root under the shared exclusive `fcntl.flock`
heavy-build lease. Each build command checked the 12 GiB estimate plus 2 GiB
reserve. Build inputs were offline. The initial full gate started with 26.818 GiB
free. Host/native dependencies and selector-conflict checks were warm; only the
granted-read selector cache had been prepared. The other nine selector caches
were initially absent. Every probe package was cleaned before compilation.

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-019"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

The first complete locked gate returned exit 0 in **223.680 s**, inside the
unchanged 600-second bound: **42 passed, zero failed, five ignored**. Artifact
checks took 139.56 s; effects took 68.39 s. Granted read, sibling denial and the
attach-secret test all passed. A prior focused run in the restricted sandbox
returned exit 101 in 18.612 s with SKIPPED: loopback bind `Operation not permitted`
before Runtime startup. That result supplies zero Runtime acceptance evidence.

The basic repository gate passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, two profiles, 28 contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`,
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`, and
`bash -n lab/agent-conformance/run.sh`.

### Falsifiers, planted and restored

The entries remain in the one `falsifiers.json`, with `command: lab`. Mutations
were applied one at a time and exact source bytes restored in a `finally` block.
F-grant-capture uses its original checker-bypass anchor and now names both tests.
Its mutated runs use synthetic in-memory canaries only. Its older control now
has a fixed assertion message; retained diagnostics exclude the canary values.
The new F-capture-inventory and F-output-inventory cover missing evidence;
F-probe-rebuild covers the independent-compilation requirement. Each of the ten
named checks failed planted with exit 101 and passed restored with exit 0.
An initial command-result filter mistook assertion text for a SKIPPED marker;
it was corrected to recognize marker lines and the affected tests were rerun.

Each table row supplies `target` and `test` for both executions of this command:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml \
  --test "$target" "$test" -- --exact --show-output
```

| Falsifier | Target / named test | Planted exit / elapsed | Restored exit / elapsed | Safe caught reason |
| --- | --- | --- | --- | --- |
| F-ac1a | `effects` / `ungranted_sibling_read_is_refused` | 101 / 9.708 s | 0 / 9.522 s | Sibling exited 0 after its explicit matching grant; denial assertion failed. |
| F-ac1b | `effects` / `granted_read_succeeds` | 101 / 9.372 s | 0 / 10.321 s | Guest content check failed after one observed grant. |
| F-grant-capture | `effects` / `grants::tests::controller_detects_credentials_without_disclosing_them` | 101 / 1.184 s | 0 / 0.731 s | Checker accepted an in-memory canary; fixed reason assertions failed. |
| F-grant-capture | `effects` / `attach_secret_stays_in_memory` | 101 / 0.445 s | 0 / 17.489 s | Checker accepted an in-memory canary; fixed reason assertions failed. |
| F-report-b | `report` / `run_table_grades_skipped_only_with_failed_test` | 101 / 0.595 s | 0 / 0.595 s | SKIPPED row changed to PASS; both report assertions failed. |
| F-report-b | `report` / `skipped_report_keeps_a_nonzero_exit` | 101 / 0.054 s | 0 / 0.245 s | SKIPPED row changed to PASS; both report assertions failed. |
| F-probe-e | `artifact` / `probe_hash_is_stable` | 101 / 17.487 s | 0 / 17.600 s | Independent default component hashes differed. |
| F-probe-rebuild | `artifact` / `probe_hash_is_stable` | 101 / 1.278 s | 0 / 19.194 s | Probe compilation message was absent after the package clean was omitted. |
| F-capture-inventory | `effects` / `attach_secret_stays_in_memory` | 101 / 1.103 s | 0 / 19.863 s | Empty expected capture inventory returned success. |
| F-output-inventory | `effects` / `attach_secret_stays_in_memory` | 101 / 1.428 s | 0 / 18.578 s | Missing required source/report surface returned success. |

The retained grant-match, ambiguity, attach, HTTP, callback, guest-content and
older artifact falsifiers keep matching anchors. The required integration
falsifiers above have fresh results. Source tests, live grant acceptance and
independent review remain separate evidence classes.

### Principles check

Answers follow the task's question wording. Paths are relative to this lane.

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name/URL instead of a code/content hash? | No | `src/identity.rs:62` retains complete bundle identity; `tests/effects.rs:34` uses the same staging path. |
| 2. New capsule or UI ambient authority? | No | `probe/src/lib.rs:69` requests a Runtime grant before the provider read; the import checks remain in `tests/artifact.rs:82`. |
| 3. A second path or copy of an operation rule? | No | `tests/common/operator.rs:65` shares census/stop; `src/report.rs:325` supplies the existing writer and credential check with one renderer. |
| 4. Does the Runtime core grow? | No | `src/harness.rs:501` extends the lane's collector; every candidate path is under `lab/agent-conformance/`. |
| 5. Do refusals fail closed with a clear reason? | Yes | `tests/common/grants.rs:71` refuses ambiguity; `src/harness.rs:321` refuses empty capture evidence. |
| 6. Does the capsule keep its logic and granted Bus calls? | Yes | `probe/src/lib.rs:69` keeps request, provider call and file-byte verification inside the guest. |
| 7. Do named tests and caught falsifiers prove the rules? | Yes | `tests/effects.rs:252` and `tests/report.rs:511` exercise credential/report rules; all ten planted checks above failed and passed restored. |
| 8. Are identity, admission and allowance separate decisions? | Yes | `tests/common/grants.rs:146` decides only from explicit pending requests and fixture entries; `src/report.rs:360` retains the receipt's authority boundary. |


### Final restored gates, receipt and handoff

After all mutations were restored and the synthetic control's assertion message
was fixed, formatting returned exit 0 in 0.134 s. The exact full locked command
above returned exit 0 in **110.842 s**: **42 passed, zero failed,
five ignored**. Its artifact group took 20.90 s and its effects group 73.59 s.
Dependencies and native/host tools were warm; each probe call still cleaned and
compiled its package. It began with 24.172 GiB free.

`lab/agent-conformance/run.sh` returned exit 0 in **112.104 s**, starting
with 24.146 GiB free. Its table has 42 passing Cargo tests, the five
unchanged BLOCKED rows, and the separate A14 PASS. Granted reads observed
matched:1, granted:1, denied:0 and exit 0 after the guest content check. Sibling
reads observed matched:0, granted:0, denied:1 and exit 1 with the exact fixture
reason. Each operator census saw two loopback sockets in both samples and
completed group stop. Both journeys passed their actual credential checks.

The verified receipt is [`target/run-table.IxQgVV/VERSIONS.json`](target/run-table.IxQgVV/VERSIONS.json),
8,447 bytes. Its native hashes match the built Runtime/provider, all ten
launched identities equal their same-run build observations, and its table and
table SHA-256 match stdout. The receipt has complete identity, command success,
and BLOCKED suite scope. Its repository commit matches HEAD with `dirty: true`.
All code, manifests, fixtures and falsifier bytes were unchanged across the final
gates. The final diff check passed; generated evidence remains ignored.

The final census found **0 task-owned processes**, and the shared probe WASM
entrypoint is absent. Passing runs removed their Homes. The **8** retained
failed-prerequisite/mutation roots each have an empty open-file census and an
explicit supervisor-review-then-remove condition in `target/task-019/lifecycle.json`.
That private inventory also names the exact selector cache, proof and receipt
paths and their removal conditions. Earlier owners retain their existing roots.

Branch/worktree inventory was rerun. The current branch holds this uncommitted
candidate for supervisor review; cached upstream divergence is zero ahead and
eight behind, with zero lane paths changed between the two committed heads.
This builder used no network fetch and changed no Git history or refs. The
supervisor owns independent development/adversarial review, commits, publication
and integration. These are successful author checks and live fixture results;
the earlier 015 review is not a review of this candidate.


## 020 — Carry 019 and refresh the consumer lockfile (2026-10-26)

Carried all 21 task-019 files from reviewed head `af77062ac` byte for byte.
The task began on `0f5660ed8`, which contains `181626722`; the initial guard
against `801da55ed` passed and HEAD contained no `tests/common/grants.rs`.
The controller, grant decisions, probe preparation, report, tests and falsifier
entries retain 019's reviewed behavior. Identity and admission supply zero
resource grants; Runtime still decides each explicit pending request.

cc-capsule-identity 004 added `ed25519-dalek` and `elastos-identity` to this
lane's path dependency. This consumer lockfile now includes their dependency
graph. Offline resolution added 85 packages: all match the versions and
checksums in `lab/capsule-identity/Cargo.lock`. All 57 original package versions
and checksums remain unchanged. Cargo also records the newly enabled dependency
edges of `crypto-common`, `digest` and `generic-array`. The lock diff has 824
added lines. The lane's root Cargo.toml stays unchanged; the probe manifest is
019's exact file.

Resolution used these commands with `CARGO_NET_OFFLINE=true`:

```sh
cargo update --offline --manifest-path lab/agent-conformance/Cargo.toml -p capsule-identity
cargo update --offline --manifest-path lab/agent-conformance/Cargo.toml -p zerocopy --precise 0.8.62
```

The second command pins the two newly added zerocopy packages to the sibling
lockfile's 0.8.62. The first command had selected 0.8.63 for those additions.
A package-key/version/source/checksum comparison confirmed the final graph.

F-lock-stale ran by hand and stays outside `falsifiers.json`. The test replaced
this lane's lock with `git show 181626722:lab/agent-conformance/Cargo.lock`, then
ran the full locked command below. It returned **101 in 0.066 s**, with
`needs to be updated but --locked was passed`. A finally block restored the
refreshed bytes. The same full command then returned **0 in 115.101 s**.
This task adds zero test-code rules beyond the carry. The eleven tests carried
from 019 cover the three live grant/memory journeys, five controller checks,
two SKIPPED-report checks and the guest's complete-file comparison. Carried
falsifiers retain their exact declarations; this task's new planted check is
F-lock-stale. The earlier section retains 019's separate falsifier evidence.

All build commands held the shared exclusive `fcntl.flock` heavy-build lease.
Each gate checked the 12 GiB build estimate plus 2 GiB reserve. The full locked
gate began with 23.681 GiB free; run.sh began with 23.437 GiB free. Host and
native outputs and all ten selector caches already existed. Cargo's initial
host test preparation took 8.58 s. Each probe invocation still cleaned and
compiled its package. Builds used offline inputs and these settings:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-020/tmp"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

| Check | Exit | Elapsed | Result |
| --- | --- | --- | --- |
| Lane formatting | 0 | 0.142 s | Clean |
| Full locked suite, without filters | 0 | 115.101 s | 42 passed, zero failed, five ignored |
| run.sh | 0 | 95.480 s | 42 passing test rows, five BLOCKED rows, A14 PASS |

Both complete gates stayed within the unchanged 600-second bound. Counts equal
019's 42 passed and five ignored. Its recorded times were 223.680 s with
partly cold selector caches and 110.842 s warm. This run used existing caches.
`attach_secret_stays_in_memory`, `granted_read_succeeds` and
`ungranted_sibling_read_is_refused` passed in both full journeys. A sandbox
preflight refused a loopback bind; the full gates ran with local fixture
process/socket access. That preflight is environment evidence only.

The basic gate passed: `git diff --check`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 contracts), `node --test
scripts/check-product-data.test.mjs` (99 passed), Runtime workspace formatting,
chain-provider formatting, and `bash -n lab/agent-conformance/run.sh`.

The same-run receipt is
[`target/run-table.RwPg2E/VERSIONS.json`](target/run-table.RwPg2E/VERSIONS.json),
8,447 bytes. Its Runtime/provider hashes match the built binaries; its ten
launched probe identities and build-only identities match this run's emitted
observations. Its table matches stdout and its table SHA-256. Identity is
complete, command success is true, and suite scope remains BLOCKED for the five
existing gaps. The receipt names the tested HEAD with `dirty: true`.

All 37 candidate source files retained their bytes through the gates. After
this append, LOG.md equals 019's file plus this section, and every other carried
file still equals 019. The specified `git diff --quiet af77062ac` comparison
returns 1 solely because the three restored new files remain outside the
index: `fixtures/granted-bytes.txt`, `fixtures/grants.json` and
`tests/common/grants.rs`. Direct blob-to-file byte comparisons include all three
and pass. The supervisor owns staging and the final indexed comparison; this
builder kept Git history, refs and index unchanged.

The final executable-path process census found **zero lane-owned processes**.
Passing fixtures retained **zero new Homes**; the shared probe entrypoint is
absent. The build lease was released. Generated evidence and cache lifecycle
entries remain ignored, with supervisor-review-then-remove conditions in the
existing local inventory. Earlier task roots retain their owners.

At the final cached upstream snapshot `e95d93cdf`, this checkout is zero ahead
and eleven behind. Those commits change zero files in this lane. Four changed
capsule-identity paths are documentation, falsifiers and its new test file;
its source, manifests and lockfile match this tested checkout. Network access
stayed disabled. The supervisor owns current-base review and integration of
this uncommitted candidate; these results are author checks.

| Principles question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name/URL replacing a code/content hash? | No | `src/identity.rs:62` retains checked bundle identity; Cargo.lock pins registry packages by checksum. |
| 2. New capsule or UI ambient authority? | No | `probe/src/lib.rs:75` requests a Runtime grant; `tests/artifact.rs:82` checks Bus-only imports. |
| 3. Second operation path or copy of a rule? | No | `tests/common/grants.rs:146` retains one pending-request controller, unchanged from 019. |
| 4. Does the trusted Runtime core grow? | No | `src/harness.rs:501` keeps collection in this lane; all candidate paths are lane-owned. |
| 5. Do refusals fail closed with a clear reason? | Yes | `tests/common/grants.rs:71` refuses ambiguous grants; F-lock-stale records Cargo's explicit locked-resolution refusal above. |
| 6. Does the capsule keep its logic and granted Bus calls? | Yes | `probe/src/lib.rs:69` keeps the grant request, provider invocation and byte check inside the capsule. |
| 7. Do named tests and caught falsifiers prove the rules? | Yes | `tests/effects.rs:252` carries the live checks; F-lock-stale above returned 101 planted and 0 restored. |
| 8. Are identity, admission and allowance separate? | Yes | `src/report.rs:360` retains the receipt's boundary; `tests/common/grants.rs:146` requires an explicit pending decision. |

004: Added the memory-write probe feature, human-space and absent-policy refusal checks, three UsersAI binding/AC-002-ARGS placeholders, fixture falsifiers F-ac2a/b/c plus F-ac2-human/write, and report/runbook coverage; the live absent-policy baseline passed (1 test, 39.855 s including build), lane/repository formatting and 99 product-data tests passed; the shared heavy-build lease remained busy through a 600 s wait, so the new refusal baselines, planted/restored falsifiers, full locked suite and run.sh remain unverified; lab falsifiers run by hand until the provider lane adds the lab arm.


## 017 — Fake host-file refusal (2026-10-26)

017: Added the `host-key-read` selector and fake `.ssh` fixture, exact manifest-refusal journey, launched-bundle receipt requirement, actual printed-line credential coverage, and F-ac8a/F-ac8-fixture/F-ac8-receipt; reused the one controller, probe, operator, spawn site and report.

The baseline asks for `localhost://Public/../../../../.ssh/id_ed25519`. The
manifest bound answers first, with the exact lifecycle reason
`Internal("capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519")`.
The fake file sits beside the data directory tree, outside every Runtime Home
root. The fixture path test derives its depth from the one Mac data-dir rule.
The fixture contains only an obvious fake marker; Runtime owns its first-run
state. The harness checks the fake bytes without opening Runtime key files.

The initial host-key filter returned exit 0 in 37.874 s (two passed). The
receipt regression returned exit 0 in 0.726 s (one passed). The extended
`attach_secret_stays_in_memory` baseline returned exit 0 in 52.000 s (one
passed). Its host-file journey observed:

```text
probe refusal effect:host-key-read exit:Some(1) reason_present:true
host key read: exit:Some(1) matched:0 granted:0 denied:0 marker_absent:true unchanged:true provider_traversal_refusal:false
```

F-ac8a was caught by **both** named tests. The controller observed one exact
request and one grant. The later provider layer refused with
`Path traversal not allowed`; the bytes stayed inside the fake fixture and
remained unchanged. Each test failed at `expected exact manifest-bound lifecycle
refusal`, after capture, printed-line, source, report and receipt checks. Its
public output was:

```text
fixture controller: matched, granted
probe refusal effect:host-key-read exit:Some(1) reason_present:false
host key read: exit:Some(1) matched:1 granted:1 denied:0 marker_absent:true unchanged:true provider_traversal_refusal:true
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 25 filtered out; finished in 9.20s
```

The second test reported the same totals with `finished in 24.90s`.
The measured command times are in the table below. This is one route and one file. It supplies zero
acceptance for other routes, key stores, signed admission or resource budgets.

All commands used the shared exclusive heavy-build lease and these settings:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-017/tmp"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects host_key -- --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report host_key_receipt -- --nocapture
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects attach_secret_stays_in_memory -- --exact --nocapture
```

The sandbox preflight refused a loopback bind (errno 1). Live runs used local
process/socket permission with offline builds. The preflight supplies zero
Runtime acceptance. The first live gate had 20.293 GiB free against a 12 GiB
build estimate plus 2 GiB reserve.

For every mutation row below, the exact command is
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test GROUP TEST -- --exact --nocapture`,
with GROUP and TEST from that row. Each mutation was applied from
`falsifiers.json` and restored in a finally block before the next mutation.
Every named test returned FAILED; none returned SKIPPED or BLOCKED.

| Mutation / test index | GROUP / TEST | Exit | Seconds |
| --- | --- | --- | --- |
| F-ac8a-0 | `effects` / `host_key_read_is_refused` | 101 | 10.326 |
| F-ac8a-1 | `effects` / `attach_secret_stays_in_memory` | 101 | 25.015 |
| F-ac8-fixture-0 | `effects` / `host_key::fixture_path_uses_the_guarded_home_rule` | 101 | 1.063 |
| F-ac8-receipt-0 | `report` / `host_key_receipt_requires_this_launched_bundle` | 101 | 0.947 |
| F-grant-capture-0 | `effects` / `grants::tests::controller_detects_credentials_without_disclosing_them` | 101 | 1.108 |
| F-grant-capture-1 | `effects` / `attach_secret_stays_in_memory` | 101 | 0.524 |
| F-output-inventory-0 | `effects` / `attach_secret_stays_in_memory` | 101 | 1.286 |
| F-capture-inventory-0 | `effects` / `attach_secret_stays_in_memory` | 101 | 1.038 |

F-ac8-fixture fails the resource-depth assertion. F-ac8-receipt fails when a
report accepts a different launched variant instead of `host-key-read`.
F-grant-capture fails both named synthetic controls; canary values remain in
memory and assertion diagnostics contain only fixed reasons. The same canary
loop covers the new printed-journey surface. F-output-inventory and
F-capture-inventory fail the required-surface checks.

The existing report executable rendered each F-ac8a run with its own Cargo
inventory, output and exit 101, using
`lab/agent-conformance/target/host/debug/report LIST OUTPUT 101 RECEIPT`.
LIST and OUTPUT are `target/task-017/F-ac8a-N.list` and
`target/task-017/F-ac8a-N.txt` under this lane, where N is 0 or 1. RECEIPT is
`target/task-017/F-ac8a-N-VERSIONS.json`. Both receipts have complete identity
and a failed outcome. These are local, ignored evidence, outside the committed
candidate. Their SHA-256 values are:

- `F-ac8a-0-VERSIONS.json`: `b2ff9f4610645eea474bf3ca7ddfe44c7becc6c00bec481fcdbe3e0228d58c14`.
- `F-ac8a-1-VERSIONS.json`: `70cbc5aac0497c1e587303be5c27b2f004ffc8c8184845ace68567a0c445f9c7`.

Both name component SHA-256
`d056c5a2d45201d334f5db1028a6a445600d695dafe9021d87883959f9086653`
and the planted manifest's bundle lab CID, whose historical digest was
`3cacbd3abf0c56ab9a92f63ae33821c67b061d4bbbadb54536e7df0df48166b9`.
The unchanged component and changed bundle identity reflect the exact manifest
mutation. The build selector, import and exclusivity checks use the same probe;
F-probe-exclusive's edit was refreshed to include the additional selector.

| Principles question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name/URL replacing code or content hash identity? | No | `tests/artifact.rs:151` stages the exact bytes through the existing component SHA-256 and checked bundle lab CID path. |
| 2. New capsule or UI ambient authority? | No | `probe/src/lib.rs:93` requests a Runtime grant before `providers::invoke`; the artifact gate checks Bus-only imports. |
| 3. Second path or rule copy? | No | `probe/src/lib.rs:85` handles the new selector in the existing read function; `tests/common/host_key.rs:72` reuses Controller. |
| 4. Does Runtime core grow? | No | `tests/common/probe.rs:50` selects a lane-owned probe feature; the candidate paths all remain under this lane. |
| 5. Do new refusals fail closed with reasons? | Yes | `tests/common/host_key.rs:99` requires the exact Runtime reason; `tests/common/grants.rs:293` rejects missing surfaces with a fixed reason. |
| 6. Self-contained logic with granted Bus calls? | Yes | `probe/src/lib.rs:85` keeps the read request, grant-scope check, invoke and lifecycle result inside the component. |
| 7. Named tests and caught falsifiers? | Yes | `tests/common/host_key.rs:39`, `tests/report.rs:553` and the mutation table above cover the fixture, live denial and receipt; F-ac8a failed both named tests. |
| 8. Identity, admission and allowance separate? | Yes | `src/report.rs:165` requires launched identity evidence while `probe/src/lib.rs:93` independently requests authority; the manifest and Runtime budgets keep their existing roles. |

### Restored gates and exact-run receipts

With all mutations restored, the required commands were:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

They used the environment and lease above. Formatting returned exit 0 in
0.084 s. The complete locked suite returned exit 0 in **301.107 s**:
**48 passed, zero failed, eight ignored**. Its artifact group passed six tests
in 150.42 s; the effect group passed 18 with eight ignored in 133.05 s. The
remaining groups passed nine harness tests, seven report tests, six Runtime
tests and two probe tests. The gate began with 24.578 GiB free. Thirteen
variants passed two independent compilations, matching pair hashes, distinct
variant hashes, Bus-only imports and every selector-pair exclusion.

`run.sh` returned exit 0 in **177.245 s**, starting with 21.051 GiB free.
It printed 48 PASS test rows, the eight inherited BLOCKED rows, and A14 PASS.
The two host-file journeys each printed the baseline line above. Relevant
exact table output:

```text
attach_secret_stays_in_memory | PASS
host_key::fixture_path_uses_the_guarded_home_rule | PASS
host_key_read_is_refused | PASS
host_key_receipt_requires_this_launched_bundle | PASS
versions_receipt (A14) | PASS
versions receipt: target/run-table.yIYXhh/VERSIONS.json
```

The local, ignored final receipt is
[`target/run-table.yIYXhh/VERSIONS.json`](target/run-table.yIYXhh/VERSIONS.json),
SHA-256 `e3dd9c8e450ff7aa2e36d9db17994dea577944930ccf0200dd61e741b19ed114`.
Its host component is
`d056c5a2d45201d334f5db1028a6a445600d695dafe9021d87883959f9086653`;
its restored complete bundle lab CID had the historical digest
`e0d8fb9541df4f6bef27eb5fdcfcd8f8820224832abb20ec987518f32ab7fc27`.
The Runtime and provider SHA-256 values match the built binaries. Every
launched entry matches this invocation's printed observations and build-only
entry. The receipt's table equals stdout, and its table digest matches.
Identity is complete and command success is true; suite scope remains BLOCKED
for the eight inherited gaps. This is the A8 acceptance receipt for the restored
candidate, with the repository commit and `dirty: true` recorded by 018.

The earlier live baselines also have local receipts, rendered by the existing
report executable from each command's saved output and exact test inventory:
`target/task-017/baseline-0-VERSIONS.json` has SHA-256
`1b18ce2307470670f5a4fa0bcdaf7bcf71d5cefc1810d924b8a7669a696cecb9`;
`target/task-017/baseline-memory-VERSIONS.json` has SHA-256
`9d0270d4b9c2f74f0811885a2c9a90168570fb2a6ab74ad0f0a6a9c752e9aa2b`.
Their command form is the report command above, with the corresponding
`baseline-0` or `baseline-memory` prefix and exit argument `0`.
These receipts also have complete identity and the restored host bundle above.

`git diff --check`, the lane's complete workspace formatting, `bash -n run.sh`,
Runtime workspace formatting and chain-provider formatting passed.
`node scripts/check-product-data.mjs` returned
`{"ok":true,"capsules":42,"profiles":2,"method_contracts":28}`;
`node --test scripts/check-product-data.test.mjs` passed all 99 tests.
The candidate diff and new files contain zero key headers or cloud-key shapes.
Every nonempty falsifier edit matches exactly once in the restored source.
The expanded selector-exclusivity test passed both full gates. A further run
of the existing F-probe-exclusive mutation met a busy shared lease before any
edit; this task claims no new catch for that existing falsifier.

The final executable-path census found **zero lane-owned processes**, and the
shared probe entrypoint is absent. The private lifecycle inventory at
`target/task-017/lifecycle.json` records this candidate, generated receipts,
build cache and retained failed-test roots. The supervisor reviews each retained
result before removing its root; earlier roots keep their prior owners. This
builder preserves those roots and unrelated worktrees.

The tested uncommitted candidate is based on `6ed2c12029ac5ca5a2d25959cd41d081fc13bb92`
(tree `25820a091f415ee0fdc5b5d971c9bc574b4f13ea`). These identify the committed
base, rather than the dirty candidate tree. Final documentation was appended
after the gates; tested code and fixture bytes stayed unchanged. The final
cached upstream comparison is zero ahead and nine behind. Those nine commits
change zero lane paths, capsule-identity paths, Runtime paths or checked build
inputs. Network fetch, Git state mutations and publication stay with the
supervisor. The supervisor also owns independent reviews and current-base
integration; the evidence here is author verification.

## 021 — cleanup census after a run

021: Extended the existing operator finish flow with a root/API/TMPDIR census, checked pending state before stop, kept cross-session live grants BLOCKED, and added the bounded earlier-run check to run.sh.

The one lsof implementation and field parser now live in `src/census.rs`.
`tests/common/operator.rs::finish_check` calls that code after group stop.
The root scan uses a scratch Home through the existing spawn site, then
`ThrowawayHome::collect_captures_from` transfers the completed tool captures
into the journey's credential-check inventory. The test PID is the only
excluded PID. The two-group control proves that the scan includes an owner
outside the operator group. The API control plants an open loopback listener;
the temp and process controls plant a file and a bounded child. Each control
removes or stops its own planted state before the clean-root assertion.

The fixture controller checks global pending requests before stop. Its grant
check reports `AC-021-GRANTS` until Runtime supplies an explicitly global live
view. The ignored `run_leaves_no_live_grant` reuses the same read journey and
requires that view; it keeps its Home on refusal. GAPS.md records the `once`
allowance and client-exit source trace, the proposed response contract and the
outside-root AC-006-STORAGE scope. F-cleanup-grant is deferred for that blocker;
synthetic scope checks supply zero live-grant acceptance.

The pre-test check is a mode of the existing report executable. It selects
only direct `target/home-*` directories, then uses the same bounded lsof path.
It prints each owner's PID and root name and exits with failure while leaving
the owner running. RUNBOOK.md gives the manual inspection and stop procedure.
The existing report annotates the read and blocked-grant rows with the exact
A10/A11/A12 lab scope, and its existing VERSIONS.json includes that same table.

All builds below used the shared exclusive heavy-build lease. Each command
checked free space against the 12 GiB estimate plus 2 GiB reserve. Loopback
binds were refused by the default sandbox (errno 1); the successful test runs
used the local process/socket permission. Every Cargo command had these
settings, and every command retained its 600-second limit:
```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-021/tmp"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

### New tests and falsifiers

New live controls: `cleanup_census_refuses_each_leftover`,
`cleanup_root_selection_finds_other_groups` and
`earlier_run_check_refuses_live_owner`. New synthetic controls:
`grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants`
and `cleanup_report_keeps_scope_and_grant_blocker`.
`run_leaves_no_live_grant` is BLOCKED, rather than a passing control.

For each entry below, apply its exact `falsifiers.json` edits, run the command,
restore the original source bytes, and run that identical command again.
All named tests failed under their mutation and passed after restoration.
The following are exact result excerpts. Full local, ignored stdout/stderr
and command/timing JSON are under `target/task-021/<ID>-{planted,restored}`;
the supervisor retains these through review. They are local evidence rather
than committed artifacts. Publication and the PR evidence record remain with
the supervisor under this builder's Git-state restriction.

#### F-cleanup-temp
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects granted_read_succeeds -- --exact --nocapture
```

Planted: exit 101, 11.230 s. Restored: exit 0, 14.109 s.
```text
planted:
cleanup census: FAIL retained:target/home-87272-1793001432349817000-0; temp leftover; processes:0 paths:[] API sockets:0 temp:1 paths:["tmp/planted-cleanup"]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)
test granted_read_succeeds ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.78s
restored:
cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)
test granted_read_succeeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 11.51s
```

#### F-cleanup-process
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects granted_read_succeeds -- --exact --nocapture
```

Planted: exit 101, 10.329 s. Restored: exit 0, 10.947 s.
```text
planted:
cleanup census: FAIL retained:target/home-91500-1793001476028182000-0; process leftover; processes:1 paths:["home", "stderr-5", "stdout-5"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)
test granted_read_succeeds ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.51s
restored:
cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)
test granted_read_succeeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 10.28s
```

#### F-cleanup-pending
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants -- --exact --nocapture
```

Planted: exit 101, 0.998 s. Restored: exit 0, 0.940 s.
```text
planted:
assertion `left == right` failed
  left: Ok(())
 right: Err("pending request leftover")
test grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 0.00s
restored:
test grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 0.00s
```

#### F-cleanup-scope
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants -- --exact --nocapture
```

Planted: exit 101, 1.247 s. Restored: exit 0, 0.916 s.
```text
planted:
assertion `left == right` failed
  left: Ok("pending:0 grants:0")
 right: Ok("pending:0 grants:BLOCKED(AC-021-GRANTS)")
test grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 0.00s
restored:
test grants::tests::cleanup_state_refuses_pending_and_requires_global_live_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 0.00s
```

#### F-cleanup-socket
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --exact --nocapture
```

Planted: exit 101, 1.339 s. Restored: exit 0, 1.569 s.
```text
planted:
called `Result::unwrap_err()` on an `Ok` value: "cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)"
test cleanup_census_refuses_each_leftover ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.23s
restored:
test cleanup_census_refuses_each_leftover ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.86s
```

#### F-cleanup-captures
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --exact --nocapture
```

Planted: exit 101, 1.212 s. Restored: exit 0, 1.617 s.
```text
planted:
called `Result::unwrap()` on an `Err` value: "capture inventory is empty"
test cleanup_census_refuses_each_leftover ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.23s
restored:
test cleanup_census_refuses_each_leftover ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.88s
```

#### F-cleanup-earlier
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --bin report earlier_run_check_refuses_live_owner -- --exact --nocapture
```

Planted: exit 101, 0.901 s. Restored: exit 0, 1.139 s.
```text
planted:
assertion failed: holders.iter().any(|h|
test earlier_run_check_refuses_live_owner ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
restored:
test earlier_run_check_refuses_live_owner ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s
```

#### F-cleanup-report
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report cleanup_report_keeps_scope_and_grant_blocker -- --exact --nocapture
```

Planted: exit 101, 0.998 s. Restored: exit 0, 0.787 s.
```text
planted:
assertion failed: text.contains("granted_read_succeeds | PASS | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included")
test cleanup_report_keeps_scope_and_grant_blocker ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s
restored:
test cleanup_report_keeps_scope_and_grant_blocker ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s
```


The first unit attempt exposed macOS lsof's exit-1 selection rule. `-V`
confirmed that unopened entries in a partly matched `+D` tree cause that exit;
there was zero stderr. The corrected root scan accepts that selection result,
parses all records and still refuses warnings and other exit codes. The
restored two-control run passed in 2.443 s. The first process mutation lacked
an explicit post-census drop and failed Rust's borrow check; that attempt is
zero falsifier credit. Its final two-edit form keeps the child through the
census and releases the borrow only after the assertions. The recorded catch
above failed on `process leftover`; the owned child's Drop stopped its group.

The restored granted baseline passed in 14.370 s. Its checked line was:
```text
cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)
```

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name/URL replacing code or content hash identity? | No | `src/report.rs:171` requires the existing granted probe identity for the ignored live-grant journey when enabled. |
| 2. New capsule or UI ambient authority? | No | `tests/common/grants.rs:236` reads existing shell routes; probe and manifest bytes retain their existing authority boundary. |
| 3. Second path or rule copy? | No | `src/census.rs:9,239` own the single lsof path and parser; `tests/common/operator.rs:71` keeps the existing finish flow. |
| 4. Does the trusted core grow? | No | `tests/common/grants.rs:580` labels the missing Runtime contract; every candidate edit stays in this lane. |
| 5. Do new refusals fail closed with reasons? | Yes | `src/census.rs:79` names process, API socket and temp leftovers; `tests/common/grants.rs:570` rejects pending requests. |
| 6. Self-contained capsule logic and granted Bus calls? | Yes | `tests/effects.rs:155` reuses the unchanged probe preparation and grant journey; the capsule keeps its existing Bus-only logic. |
| 7. Named tests and caught falsifiers? | Yes | `tests/runtime.rs:238`, `tests/common/grants.rs:737`, `src/bin/report.rs:63` and `tests/report.rs:599` are covered by the eight caught mutations above; live grants stay BLOCKED. |
| 8. Identity, admission and allowance separate? | Yes | `tests/effects.rs:209` checks grant state independently of probe identity and the operator's unsigned-fixture admission. |

### Restored gates and same-run receipt

The restored candidate passed these commands with the environment above:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
lab/agent-conformance/run.sh
```

Formatting returned exit 0. The full locked suite returned exit 0 in
**209.243 s**, with **53 passed, zero failed and nine ignored**. The command
began with 55.019 GiB free. Group results: one report-binary test, six artifact
tests, 19 effect tests with nine ignored, nine harness tests, eight report
tests, eight Runtime tests and two probe tests. The unchanged deadline was
600 seconds. The two operator tests exercised the extended finish flow.

`run.sh` returned exit 0 in **188.245 s**, starting with 54.661 GiB free.
Its pre-test owner check passed, and its table contained 53 PASS test rows,
nine BLOCKED rows, zero SKIPPED rows, and A14 PASS. The eight inherited blocked
rows kept their IDs. Earlier live tests passed, and the existing synthetic
SKIPPED-grading tests passed. The ninth blocker is AC-021-GRANTS. Exact rows:

```text
granted_read_succeeds | PASS | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included
run_leaves_no_live_grant | BLOCKED (AC-021-GRANTS) | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included
ungranted_sibling_read_is_refused | PASS | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included
versions_receipt (A14) | PASS
versions receipt: target/run-table.9L2bth/VERSIONS.json
```

The local, ignored receipt is
[`target/run-table.9L2bth/VERSIONS.json`](target/run-table.9L2bth/VERSIONS.json),
SHA-256 `fb99835f51e448e8ebf18413b23c55a3086860fce31cfb7210ff2e05ec784047`.
Its table equals this invocation's table, and the table digest matches.
The Runtime and localhost-provider hashes match the exact native binaries
under this lane's `target/runtime/debug/`. Identity is complete and command
success is true. The suite's acceptance scope remains BLOCKED for its nine
recorded contract gaps. This receipt names the committed base with
`dirty: true`; it does not identify the uncommitted candidate as HEAD.

`git diff --check`, `bash -n lab/agent-conformance/run.sh`, Runtime workspace
formatting and chain-provider formatting also returned exit 0.
`node scripts/check-product-data.mjs` reported
`{"ok":true,"capsules":42,"profiles":2,"method_contracts":28}`;
`node --test scripts/check-product-data.test.mjs` passed all 99 tests.
All eight new falsifier definitions still match the restored candidate.
There is one lsof executable path and one child spawn site in the lane.

After the table run, the exact command
`lab/agent-conformance/target/host/debug/report --check-earlier-runs`
returned exit 0 in **0.220 s**, with empty stdout/stderr: zero remaining
process owners under earlier Homes. Passing tests removed their Homes.
Eight failed Homes from controls and mutations remain for supervisor review;
`target/task-021/lifecycle.json` records their paths, evidence and cleanup
condition, plus the receipt and rebuildable cache lifecycle. Other owners'
worktrees and earlier retained data remain under their existing ownership.

The tested source is based on commit
`f7ff129c2cdb74cf1c7faba4a7b3e8b3209b3054`, base tree
`6ec7f334c5c9e7d54c99a4ee847f1d265f1419b5`. The current task worktree is dirty
only under this lane. The branch/worktree inventory was rerun; the builder
created or removed zero refs or worktrees. The cached upstream comparison is
zero ahead and nine behind. Those nine commits change zero lane paths,
capsule-identity paths, Runtime paths or the component build script. The
supervisor owns fresh integration, independent review, PR evidence and Git
publication. Final documentation was appended after the gates; tested code
and fixtures retain the restored bytes.


## 022 — Run memory falsifiers and grade blocker lists (2026-10-26)

022: Ran F-ac2c, F-ac2-human and F-ac2-write from clean source, retired the two blocked principal falsifiers, and replaced the report's special case with one blocker-list rule and its caught falsifier.

`report::grade` splits the complete blocker reason on `;`, trims each part,
and joins whole parts with `; `. An empty reason or part receives FAIL.
`run_table_grades_blocker_lists_by_one_rule` exercises the existing parser
with single IDs, multi-word names, joint blockers, whitespace and empty parts.
The existing joint-row assertion remains active; the older `RT3 model grant`
fixture now expects its complete reason. F-ac2a and F-ac2b are retired under
`UsersAI binding; AC-002-ARGS`, with their named live-test return conditions.
GAPS.md and RUNBOOK.md retain the intended mutations.

### Execution boundary and commands

The three existing falsifiers started at clean source commit
`f9d2b48f8160398e843e0d656d2771fefc4fef29`, tree
`26777084c404f2c02cf604bb52569a0ad6b3d8dd`. Before each baseline and after each
restored run, `git status --porcelain lab/agent-conformance` returned empty.
Each baseline passed before its mutation was applied. Each edit matched once;
the original bytes were restored in a Python `finally` block. For F-ac2c,
`old: ""` required an absent file, created with `open('xb')`; restoration
removed only that added file. The assertion failure below is the deliberate
fixture mutation, with a passing unmutated Runtime baseline.

All four falsifiers used the shared exclusive `fcntl.flock` heavy-build lease
from RUNBOOK.md. The parent opened the existing lock read-only at
`git rev-parse --path-format=absolute --git-common-dir` plus
`local-ai-heavy-build.lock`. Both lease acquisitions took 0.000 seconds at
three-decimal precision. The retry bound was 180 seconds. The parent kept the
lease through each sequential command and closed it on completion; child
commands received zero lease descriptors. Every Cargo command had a
600-second limit. Initial volume free space was 53.024 GiB; each build batch
checked the 12 GiB build allowance plus 2 GiB reserve.

The default sandbox's loopback bind preflight returned
`[Errno 1] Operation not permitted`. The measured runs used local process and
socket permission with offline Cargo, the existing loopback operator fixture,
and these settings from the repository root:

```sh
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-022/tmp"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
```

The commands below are the exact Cargo argument lists. Each ran unchanged
at baseline, planted and restored. Inline Python read each entry from
`falsifiers.json` and applied its byte strings with these operations (there
is no added runner file):

```python
old = edit['old'].encode()
new = edit['new'].encode()
original = path.read_bytes() if path.exists() else None
if old == b'':
    assert original is None
    with path.open('xb') as out:
        out.write(new)
else:
    assert original is not None and original.count(old) == 1
    path.write_bytes(original.replace(old, new, 1))
# In finally, after the planted command:
if original is None:
    path.unlink(missing_ok=True)
else:
    path.write_bytes(original)
```

Full output and command/timing JSON under `target/task-022/` are local, not
committed. The excerpts below are copied from those actual runs, including
the libtest result and assertion panic. All named tests ran: none of these
falsifier results is an ignored test, build failure or environmental skip.

### F-ac2c — CAUGHT

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects no_policy_file_does_not_mean_allow -- --exact --nocapture
```

Baseline (exit 0, 40.014 seconds):

```text
fixture read: exit:Some(1) matched:0 granted:0 denied:0 content_error:false
probe refusal effect:granted-read exit:Some(1) reason_present:true
test no_policy_file_does_not_mean_allow ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 38.23s
```

Planted (exit 101, 9.243 seconds):

```text
fixture read: exit:Some(0) matched:1 granted:1 denied:0 content_error:false
thread 'no_policy_file_does_not_mean_allow' (34637908) panicked at tests/effects.rs:263:9:
assertion `left == right` failed: no-policy acceptance failed; private triage required
  left: Some(0)
 right: Some(1)
test no_policy_file_does_not_mean_allow ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.14s
```

Restored (exit 0, 37.563 seconds):

```text
fixture read: exit:Some(1) matched:0 granted:0 denied:0 content_error:false
probe refusal effect:granted-read exit:Some(1) reason_present:true
test no_policy_file_does_not_mean_allow ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 37.42s
```

After restoration, `git status --porcelain lab/agent-conformance` returned empty.

### F-ac2-human — CAUGHT

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects agent_cannot_read_human_space_without_grant -- --exact --nocapture
```

Baseline (exit 0, 9.660 seconds):

```text
probe refusal effect:human-read exit:Some(1) reason_present:true
test agent_cannot_read_human_space_without_grant ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.54s
```

Planted (exit 101, 9.413 seconds):

```text
probe refusal effect:human-read exit:Some(0) reason_present:false
thread 'agent_cannot_read_human_space_without_grant' (34644376) panicked at tests/effects.rs:90:5:
expected nonzero exit and lifecycle refusal Internal("localhost://Users/self requires a principal-scoped launch context")
test agent_cannot_read_human_space_without_grant ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.29s
```

Restored (exit 0, 9.437 seconds):

```text
probe refusal effect:human-read exit:Some(1) reason_present:true
test agent_cannot_read_human_space_without_grant ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.33s
```

After restoration, `git status --porcelain lab/agent-conformance` returned empty.

### F-ac2-write — CAUGHT

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects ungranted_memory_write_is_refused -- --exact --nocapture
```

Baseline (exit 0, 9.816 seconds):

```text
probe refusal effect:memory-write exit:Some(1) reason_present:true
test ungranted_memory_write_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.71s
```

Planted (exit 101, 9.233 seconds):

```text
probe refusal effect:memory-write exit:Some(0) reason_present:false
thread 'ungranted_memory_write_is_refused' (34660662) panicked at tests/effects.rs:90:5:
expected nonzero exit and lifecycle refusal Internal("capsule manifest does not declare authority for localhost://UsersAI/self/.AppData/ElastOS/AgentHost/tasks/conformance/memory")
test ungranted_memory_write_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.11s
```

Restored (exit 0, 9.163 seconds):

```text
probe refusal effect:memory-write exit:Some(1) reason_present:true
test ungranted_memory_write_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out; finished in 9.05s
```

After restoration, `git status --porcelain lab/agent-conformance` returned empty.

### F-report-blocker-list — CAUGHT

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report run_table_grades_blocker_lists_by_one_rule -- --exact --nocapture
```

This new test and grader are the uncommitted task candidate. The builder's
Git-state restriction prevents a committed clean-tree baseline for new code.
The sequence instead checked the original candidate bytes and identical
`git status --porcelain lab/agent-conformance` before and after restoration;
it does not claim this candidate is HEAD. Baseline SHA-256 values:

- `src/report.rs`: `d85714b1cc38a739bcc2927bbcc5afa35b6fe19d9fc21f1a2a45d405a69ae08c`.
- `tests/report.rs`: `459df899a9676022ff99e8a5a66e699282170ece9c0317d30848bb13bc583eca`.

Baseline (exit 0, 1.481 seconds):

```text
test run_table_grades_blocker_lists_by_one_rule ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s
```

Planted (exit 101, 1.205 seconds):

```text
thread 'run_table_grades_blocker_lists_by_one_rule' (34684454) panicked at tests/report.rs:112:9:
assertion `left == right` failed: blocker reason: "UsersAI binding"
  left: ("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncase | BLOCKED (UsersAI)\n", true)
 right: ("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncase | BLOCKED (UsersAI binding)\n", true)
test run_table_grades_blocker_lists_by_one_rule ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s
```

Restored (exit 0, 0.941 seconds):

```text
test run_table_grades_blocker_lists_by_one_rule ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s
```

### Gates and remaining acceptance

Commands used the same environment and shared lease as the falsifier runs:

```sh
cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
```

Formatting passed (exit 0, 0.129 seconds). The first full locked suite returned
exit 101 after 212.460 seconds. Its effect target passed 19 tests with nine
explicit blockers; its report target passed all nine tests, including the
existing joint-row assertion and the new blocker-list test. The unchanged
runtime target failed its final cleanup census:

```text
test fixture_operator_sockets_are_loopback_only ... FAILED
thread 'fixture_operator_sockets_are_loopback_only' (34746555) panicked at tests/runtime.rs:201:14:
final census and operator group stop: "cleanup census: FAIL retained:target/home-6868-1793003241614105000-20; process leftover; processes:2 paths:[\"stderr-37\", \"stdout-37\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)"
test result: FAILED. 7 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 14.35s
```

The task leaves the 021 cleanup implementation and assertions intact. The
failure above remains part of the gate record even if a later run passes.
The three deliberately failed Homes and this gate's failed Home had completed
operator group-stop checks. An additional `lsof -nP +D <root> -Fpf` returned
exit 1 with empty stdout and stderr for each root; those four task-owned roots
were then removed. Their data contents were kept out of inspection.

Additional required checks passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, two profiles, 28 method
contracts), `node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
`falsifiers.json` parses with 60 active IDs and two retired IDs, all unique.
Cargo.toml and Cargo.lock remain byte-identical to HEAD.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name/URL used where a code/content hash belongs? | No | `src/identity.rs:62` retains checked bundle identity; the change affects report reasons only. |
| 2. New capsule or UI ambient authority? | No | `probe/src/lib.rs:91` retains the grant request; its planted changes were restored byte for byte. |
| 3. Second operation path or copy of a rule? | No | `src/report.rs:11` remains the one grader; its hard-coded joint-blocker case is removed. |
| 4. Runtime core grows? | No | `src/report.rs:15` implements the rule in this lane's report; every candidate path is under this lane. |
| 5. Refusals fail closed with a clear reason? | Yes | `src/report.rs:17` rejects every empty part with FAIL; `tests/report.rs:106` checks the malformed inputs. |
| 6. Capsule logic remains inside, using granted Bus calls? | Yes | `probe/src/lib.rs:91` keeps the capability request before the provider call; the probe is unchanged. |
| 7. Named tests and caught falsifiers prove the new rule? | Yes | `tests/report.rs:94` fails under F-report-blocker-list; this section records all four baseline/fail/restored sequences. |
| 8. Identity, admission and allowance stay separate? | Yes | `src/report.rs:374` retains the receipt's explicit identity/admission/grant boundary. |

### Gate retry and handoff

The follow-up attempted to acquire the same lease before rerunning
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime fixture_operator_sockets_are_loopback_only -- --exact --nocapture`.
Its bounded 180-second wait ended with exit 75 and this exact output:

```text
BLOCKED: shared heavy-build lease remained busy for 180 seconds
```

That command and its conditional full-suite retry both remained unstarted.
This wait concerns the gate retry only; the four falsifier sequences above
completed under the lease and keep their recorded results. The full locked
gate remains FAIL, with its cleanup-census result above. The supervisor owns
the next full gate run and the clean committed-candidate check for the new
falsifier; the builder leaves all Git state unchanged.

The final source check matched the recorded report/test SHA-256 values,
confirmed one occurrence of the new mutation anchor, confirmed original
probe and Cargo manifest/lock bytes, and confirmed the policy file is absent.
All six changed files are lane-owned. The local lifecycle inventory records
the candidate worktree, proof retention through supervisor review, existing
build caches for the pending rerun, and the four removed test Homes. The
falsifier commands released their lease; the blocked retry acquired none.

At handoff, cached upstream divergence is 0 ahead and 0 behind.
Network access stayed disabled; the supervisor owns fresh remote validation.

## 023 — Two seeded instances (2026-10-26)

023: Extended the existing probe read, fixture seed/controller and client collector for two concurrent instance builds, separate session grants and directories, two timed overlap barriers, checked journey evidence, and same-run version receipts.

The scope is **process-isolation lab half of A3, A6 and A9**. The two clients
use separate throwaway Homes and borrow one operator through the existing
coordinate override. Each guest reads its own seeded file and checks the
complete response, then requests its sibling file. The controller observes
both sessions before each decision stage. The first baseline used one client
Home and failed before the second barrier; separate client Homes reuse the
landed parallel journey and give the passing baseline below. AC-006-STORAGE
keeps the existing shared client-storage limit.

The builder used the task 016 summary and round-1 quote supplied in task 023.
The historical queue and builder note are outside this repository and stayed
outside the file reads. The repository has no humanizer skill; this record uses
plain statements of behavior and ownership. Every edit is in this lane.
The builder preserved Git state and Cargo manifests/lockfiles.

All builds hold the existing shared exclusive heavy-build lease through a
read-only file descriptor and `fcntl.flock`. The initial volume had 52 GiB free;
each batch checked a 12 GiB estimate plus the required 2 GiB reserve. The
default sandbox refused loopback bind. The test commands use local process
and socket permission, offline Cargo and only the fixture loopback operator.
Local proof files under `target/task-023-current/` are untracked; the supervisor
owns their review and removal. Runtime credentials stay in memory and
Runtime-owned fixture state.

Commands use these settings from the repository root:

```sh
export CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$PWD/lab/agent-conformance/target/host"
export CARGO_BUILD_BUILD_DIR="$PWD/lab/agent-conformance/target/host-build"
export TMPDIR="$PWD/lab/agent-conformance/target/task-023-current"
```

Each live filtered run first collects the same command's `--list`, then its
`--exact --show-output` result. The existing report binary reads those two
files and the Cargo exit code and writes that run's exclusive VERSIONS.json.
Each mutation below uses the exact `old`/`new` bytes in `falsifiers.json` once;
a `finally` block restores the original bytes before the restored run.

### F-ac3b: baseline, planted, restored

grant instance 2 a read of instance 1 file. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects instance_grant_does_not_authorise_sibling -- --exact --show-output
```

```text
baseline:
test instance_grant_does_not_authorise_sibling ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.38s
planted:
test instance_grant_does_not_authorise_sibling ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.93s
restored:
test instance_grant_does_not_authorise_sibling ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.74s
```

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects attach_secret_stays_in_memory -- --exact --show-output
```

```text
baseline:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 36.65s
planted:
test attach_secret_stays_in_memory ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 42.24s
restored:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 40.40s
```

Both planted runs failed with `each instance must receive its sibling denial with the fixture reason`. Instance 2 exited with code 0 after the extra grant. Every live run has a local, uncommitted receipt at
`target/task-023-current/F-ac3b-<phase>-<test>/VERSIONS.json`.

### F-ac3c: baseline, planted, restored

move instance 2 own file into instance 1 directory. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects two_instances_overlap_with_separate_grants -- --exact --show-output
```

```text
baseline:
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.25s
planted:
test two_instances_overlap_with_separate_grants ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 14.85s
restored:
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 13.02s
```

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects attach_secret_stays_in_memory -- --exact --show-output
```

```text
baseline:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 47.03s
planted:
test attach_secret_stays_in_memory ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 44.12s
restored:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 43.25s
```

Both planted runs failed with `separate-directory check: instance files share a directory`. The instance controller made zero decisions before this failure. Every live run has a local, uncommitted receipt at
`target/task-023-current/F-ac3c-<phase>-<test>/VERSIONS.json`.

### F-ac3d: baseline, planted, restored

start the second client only after the first exits. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects two_instances_overlap_with_separate_grants -- --exact --show-output
```

```text
baseline:
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.95s
planted:
test two_instances_overlap_with_separate_grants ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 39.19s
restored:
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 11.99s
```

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects attach_secret_stays_in_memory -- --exact --show-output
```

```text
baseline:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 37.81s
planted:
test attach_secret_stays_in_memory ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 64.40s
restored:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 37.90s
```

Both planted runs failed with `overlap: barrier exceeded 10 seconds`. The measured overlap was zero and the row remained FAIL. Every live run has a local, uncommitted receipt at
`target/task-023-current/F-ac3d-<phase>-<test>/VERSIONS.json`.

### F-instance-receipt: baseline, planted, restored

accept an instance journey without its second launched identity. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test report instance_receipt_requires_both_launches_and_scope -- --exact --show-output
```

```text
baseline:
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
planted:
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
restored:
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

### F-instance-bytes: baseline, planted, restored

accept only an instance file response prefix. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance-probe --lib tests::guest_checks_each_instance_file -- --exact --show-output
```

```text
baseline:
test tests::guest_checks_each_instance_file ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
planted:
test tests::guest_checks_each_instance_file ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
restored:
test tests::guest_checks_each_instance_file ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

### F-instance-selector: baseline, planted, restored

allow an instance selector without the granted-read effect. All named tests failed with the fault and passed after exact restoration.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test artifact instance_subselectors_require_one_granted_read -- --exact --show-output
```

```text
baseline:
test instance_subselectors_require_one_granted_read ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.19s
planted:
test instance_subselectors_require_one_granted_read ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.07s
restored:
test instance_subselectors_require_one_granted_read ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.21s
```

### F-instance-evidence: baseline, planted, restored

accept missing printed instance evidence. All named tests failed with the fault and passed after exact restoration.
```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects grants::tests::instance_journey_requires_all_printed_surfaces -- --exact --show-output
```

```text
baseline:
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
planted:
test grants::tests::instance_journey_requires_all_printed_surfaces ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.07s
restored:
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
```


### Existing F-grant-capture: reused shared checker

Both named tests pass, fail with the in-memory credential check disabled, and
pass after restoration. The failure text contains fixed reasons.

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects grants::tests::controller_detects_credentials_without_disclosing_them -- --exact --show-output
```

```text
baseline:
test grants::tests::controller_detects_credentials_without_disclosing_them ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
planted:
test grants::tests::controller_detects_credentials_without_disclosing_them ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
restored:
test grants::tests::controller_detects_credentials_without_disclosing_them ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.00s
```

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -p agent-conformance --test effects attach_secret_stays_in_memory -- --exact --show-output
```

```text
baseline:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 44.57s
planted:
test attach_secret_stays_in_memory ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 30 filtered out; finished in 0.93s
restored:
test attach_secret_stays_in_memory ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 45.85s
```

The existing F-grant-service anchor now names `service(&mut self)?`, matching
the collector callback that exposes child liveness to the same controller.
Its mutation still removes that one service call. Existing F-ac2 entries and
the report grading rule stay unchanged.

### Final gate and same-run receipt

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` and
its `--all` counterpart passed on the restored source. `bash
lab/agent-conformance/run.sh` passed with exit 0 in 261.383 seconds. That script
ran the complete `cargo test --locked --no-fail-fast --manifest-path
lab/agent-conformance/Cargo.toml -- --format pretty --color never --show-output`
gate. Its table records 60 passing tests, nine existing BLOCKED tests and a
passing A14 receipt. All 15 probe variants have launched identities. The
three instance journeys measured 0.228965, 0.238439 and 0.380878 seconds of
overlap; both barriers completed each time.

The same-run receipt is local and uncommitted:
`target/run-table.rPN6Je/VERSIONS.json`, SHA-256
`b094fdfd963b217f600d27f97dea5c073b2d2f57300b85b7c605c6c3c4daee62`.
It records `identity_status: complete`, `cargo_success: true` and
`suite_outcome: BLOCKED` because the nine existing blocker rows remain open.
Its repository dirty flag is true: this is the builder's uncommitted candidate.
The final full-run transcript is in `target/task-023-current/full-run.txt`.

Additional checks passed: `git diff --check`, `bash -n
lab/agent-conformance/run.sh`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
The probe manifest, both Cargo manifests and the lane lockfile retain their
original bytes. The artifact gate passes the existing manifest bound for both
directories. Every new mutation anchor is restored; F-ac2 entries and grading
remain unchanged. The generated probe entrypoint is absent after the gate.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name/URL where code or content needs a hash? | No | `src/identity.rs:50` stages each component by SHA-256 and obtains its complete bundle lab CID; `tests/artifact.rs:137` checks both builds and distinct hashes. |
| 2. New ambient capsule or UI access? | No | `probe/src/lib.rs:117` requests each read grant before the one provider invocation; the artifact import gate passed. |
| 3. Second operation path or copy of a rule? | No | `tests/common/grants.rs:309` extends the existing seed route; `poll` at line 358 remains the only fixture decision path. |
| 4. Runtime core grows? | No | `tests/effects.rs:496` adds the lab journey; every changed path is inside this lane. |
| 5. Refusals fail closed with a clear reason? | Yes | `tests/common/grants.rs:164` rejects missing overlap, early exits and expired barriers; `tests/effects.rs:461` requires each delivered denial reason. |
| 6. Guest logic remains self-contained and uses granted Bus calls? | Yes | `probe/src/lib.rs:117` keeps both reads in the guest; `read_bytes_match` at line 199 checks complete bytes. |
| 7. Named tests and caught falsifiers prove the rules? | Yes | `tests/effects.rs:496` and line 501 pass/fail/pass for F-ac3b/c/d; the four added unit-rule falsifiers and reused F-grant-capture have the sequences above. |
| 8. Identity, admission and allowance stay separate? | Yes | `src/report.rs:172` requires both launched identities as evidence; `tests/common/grants.rs:358` sends explicit session grant decisions for exact resources. |

### Local lifecycle and handoff

The collector drained the client groups and the existing operator stop and
census completed in each live fault run. Before the full gate, a direct
`lsof -nP +D <task-owned root> -Fpf` returned exit 1 with empty stdout and stderr
for all 20 retained roots from this attempt. Those roots were removed after
reviewing the failure evidence. Existing owners' roots were preserved. The
full gate retained zero new roots. Afterwards the existing
`target/host/debug/report --check-earlier-runs` returned exit 0 with empty
output. The build lease is released; test processes have ended.

The local machine-readable record is
`target/task-023-current/lifecycle.json`. It records this worktree's role,
commit/tree, dirty state, cached divergence, branch/worktree inventory, removed
fixture roots, and review-bound retention for the local proof and build caches.
The supervisor owns commit, current-base compatibility and review. The builder
ran zero Git mutations and used zero remote network requests. At this check,
the cached spike base was 21 commits ahead of this checkout (0 ahead, 21 behind);
other workers advanced that fetched ref during the task.

## 024 — receipt uses the identity owner's parser

`Identities::observe_probe` now parses the bundle lab CID as
`capsule_identity::LabCid`; synthetic receipt values use `encode_entries`, and
the runbook and historical notes leave the printed form to that library.
The historical notes retain their recorded digest bytes. This follows
cc-capsule-identity's ninth-run request (26 Oct): "please replace that check
with `probe.bundle_lab_cid.parse::<capsule_identity::LabCid>().is_ok()` (the one
claim check, and it adds no new dependency or lock change; 013 has merged,
PR #170)." The `malformed bundle lab CID: <effect>` refusal stays the same.

The existing `versions_receipt_rejects_incomplete_identity` test now also
changes the last character of an encoder-produced CID to `X` and requires
`malformed bundle lab CID: default`. Its existing `sha256:wrong` case stays.
The synthetic seeds and the report-wiring-only evidence comment stay intact.
The newer instance receipt fixture also uses the same synthetic bundle helper.

### Falsifier proof

All ten report tests passed before the mutation. The new
`F-versions-lab-cid` has `command: lab` and names only
`versions_receipt_rejects_incomplete_identity`. Its edit replaces the parser's
success check with `!probe.bundle_lab_cid.is_empty()`. Applied by hand, this
command failed with exit 101:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report versions_receipt_rejects_incomplete_identity -- --exact
```

The assertion at `tests/report.rs:291` failed with:

```text
expected malformed bundle lab CID: default; got ["conflicting probe identity: default"]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out
```

The source was restored byte for byte in a `finally` block. The identical
command then passed: one passed, zero failed, nine filtered out. The new
falsifier's anchor matches the restored source exactly once. Its failed-test
root was removed after an empty open-holder check.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `tests/report.rs:165` obtains synthetic bundle identity from the owner's encoder. |
| 2. New ambient capsule or UI authority? | No | `src/report.rs:254` parses receipt data; the capsule and grant paths retain their behavior. |
| 3. Second path or copy of a rule? | No | `src/report.rs:256` delegates the printed-value check to `LabCid`. |
| 4. Runtime core grows? | No | `src/report.rs:241` contains the only production logic change, inside this lab lane. |
| 5. Refusal fails closed with a clear reason? | Yes | `src/report.rs:259` returns the existing malformed-bundle reason on parse failure. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `probe/src/lib.rs:138` and `:146` retain the grant request followed by provider invocation. |
| 7. Named test and caught falsifier prove the rule? | Yes | `tests/report.rs:281` passes after restoration and fails for `falsifiers.json:491`'s planted check. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/report.rs:389` preserves the receipt's version-evidence boundary; `RUNBOOK.md:216` keeps allowance separate. |

### Final checks and handoff

The required lane formatting check and complete `cargo test --locked
--manifest-path lab/agent-conformance/Cargo.toml` passed under the shared
heavy-build lease in 241.13 seconds: 60 passed, zero failed, nine existing
blocked tests ignored. This includes all four named receipt acceptance tests,
`instance_receipt_requires_both_launches_and_scope`, and
`attach_secret_stays_in_memory`, which uses the shared grant fixture value.
The commands used `RUST_TEST_THREADS=2`, `CARGO_INCREMENTAL=0`,
`CARGO_NET_OFFLINE=true`, and the existing lane-local `target/host` and
`target/host-build` directories. Free space exceeded the documented 12 GiB
build allowance plus 2 GiB reserve.

The first full-gate attempt stopped at `earlier_run_check_refuses_live_owner`
because the sandbox denied child process-group inspection. A rerun with local
process inspection and loopback fixture access passed that test and the full
gate above. The first attempt's disposable root was removed after an empty
open-holder check. This environment refusal supplies zero Runtime evidence.

Additional checks passed: `git diff --check`,
`node scripts/check-product-data.mjs` (42 capsules, two profiles, 28 method
contracts), `node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
The task's exact search for the old printed form returned empty output
(exit 1). JSON validation confirmed a unique new falsifier ID and its restored
anchor. Both `Cargo.toml` and `Cargo.lock` are byte-identical to the base `HEAD`.

The candidate changes six files, all inside this lane. The local, ignored
`target/task-024-current/lifecycle.json` records the branch/worktree inventory,
source identity, disposable-root cleanup and retention decisions. The
supervisor owns commit, current-base compatibility, review and publication;
the builder performed zero Git mutations. The cached upstream had advanced
three commits at the handoff check (zero ahead, three behind). The required
remote refresh stays with the supervisor under this builder's offline scope.
The existing `target/host/debug/report --check-earlier-runs` then exited 0
with empty output. Fixture processes have ended and the heavy-build lease is
released. Build caches remain reusable lane artifacts with supervisor-owned
cleanup conditions in the local inventory.

## 025 — CID launch requires a verified content provider

Added the two bounded CID-refusal tests and the ignored `capsule_named_by_hash`
journey in `tests/runtime.rs`. The synthetic CID comes from the identity
owner's encoder. Both refusals precede CID validation and give zero evidence
that the CID itself was checked. `tests/common::write_component_home` now owns
the single repository-entry copy, executable-byte install and manifest stamp;
`write_operator_home` calls it and retains its config writer and F-ac1i anchor.
The source-backed verdict in GAPS.md is `AC-025-CID`; RUNBOOK.md names all
three rows. The full journey needs the directory CID integration, an offline
content fixture, and cleanup of the kept materialized directory.

### F-cid-provider — caught by hand

All commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, the lane-local `target/host` and `target/host-build`
directories, and the exclusive shared `local-ai-heavy-build.lock` lease.
The same command ran in each step:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash -- --exact --show-output
```

Unmutated, exit 0:

```text
test run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.86s
```

Planted, exit 101: F-cid-provider replaced the fixed byte string's digest with
`Sha256::digest(script)`. Runtime then executed the inert script. Its marker
existed, and the assertion at `tests/runtime.rs:120` failed:

```text
test run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash ... FAILED
checksum refusal must happen before the content provider script is spawned
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 2.14s
```

Restored byte for byte in a `finally` block, exit 0:

```text
test run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.73s
```

The test named by this falsifier failed, so the result is **CAUGHT**. The
restored F-cid-provider anchor and F-ac1i's original `old` text each occur
exactly once. The two new refusal tests also passed together with
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test
runtime run_by_cid -- --show-output`: two passed, zero failed, nine filtered
out, 2.46 seconds in libtest. The real IPFS provider and Kubo were neither
installed nor run. The planted provider was a mode-0755 shell script that
created one in-root marker and exited 1.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New code/content name or URL where a hash belongs? | No | `tests/runtime.rs:67` gets the printed CID from `encode_entries`; line 114 stamps a SHA-256. |
| 2. New ambient capsule or UI access? | No | `tests/runtime.rs:74` uses the existing guarded launch; `tests/common/mod.rs:51` guards the fixture Home. |
| 3. Second operation path or copy of a rule? | No | `tests/common/mod.rs:44` owns the shared entry copy and stamp; both callers use it. |
| 4. Runtime core grows? | No | `tests/runtime.rs:63` adds only lab evidence; all changed files stay inside this lane. |
| 5. Refusals fail closed with a clear reason? | Yes | `tests/runtime.rs:80,101,128` require failure and the specific missing-provider or complete checksum reason. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/runtime.rs:65` stops at provider resolution; the probe and its existing Bus calls retain their bytes. |
| 7. Named tests and caught falsifiers prove the new rule? | Yes | `tests/runtime.rs:109` passed, failed on the script marker for F-cid-provider, and passed restored; the full journey stays ignored at line 142. |
| 8. Identity, admission and allowance stay separate? | Yes | `GAPS.md:140` separates lab identity from content resolution; line 158 keeps admission, grants and budgets separate. |

### Final checks and writer parity

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` passed.
`bash lab/agent-conformance/run.sh` passed with exit 0 in 254.09 seconds under
the same environment and build lease. Its full lane command was:

```sh
cargo test --locked --no-fail-fast --manifest-path lab/agent-conformance/Cargo.toml -- --format pretty --color never --show-output
```

Cargo's table contains 62 passing tests and ten BLOCKED tests, plus a passing
A14 receipt. The new rows and the required operator regressions are:

```text
run_by_cid_without_content_provider_is_refused | PASS
run_by_cid_refuses_content_provider_whose_bytes_differ_from_its_hash | PASS
capsule_named_by_hash | BLOCKED (AC-025-CID)
serve_refuses_provider_whose_bytes_differ_from_its_hash | PASS
fixture_operator_starts_ready_and_stops_cleanly | PASS
```

The same-run receipt reports `identity_status: complete`, `cargo_success:
true`, and `suite_outcome: BLOCKED`. Its SHA-256 is
`191ae847015501a9d065c95faa9249d2437495c9281b9ddbd5433cfb88bc0f83`.
The receipt describes the uncommitted builder candidate, with a dirty tree;
its source identity is separate from the future reviewed commit. The full
CID journey remains open and receives zero passing credit.

The original operator writer produced its manifest and config before the
sandbox denied the baseline test's loopback bind (`Operation not permitted`).
That environment refusal supplied zero Runtime acceptance evidence. The full
run with local fixture access passed both required operator tests above.
The refactored writer's operator outputs matched the saved original bytes;
every newly observed operator manifest in the full run had SHA-256
`3431d423c615464533087b49d332fc6b555859a21d0f3a21c7adb611334010f1`,
and each config had
`49a48bd70178471d63248e71095fa2e3a3f32da5262be82681b454c5f64df437`.
The executable-byte/hash assertions in the existing provider-refusal test
also passed. Both `Cargo.toml` and `Cargo.lock` remain byte-identical to HEAD.

Additional checks passed: `git diff --check`, `bash -n
lab/agent-conformance/run.sh`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
JSON validation found unique falsifier IDs; both required mutation anchors
were restored and each matched once.

The two task-owned failed roots were removed after their results were reviewed
and `lsof -nP +D <root> -Fpf` returned exit 1 with empty output. The full run
retained zero new Home roots. The final existing `report --check-earlier-runs`
command returned exit 0 with empty output. The build lease is released.
The local ignored lifecycle inventory records the worktree, source identity,
fixture cleanup, and review-bound retention of the proof and build caches.
Other owners' roots and worktrees retain their ownership.

All six changed files are inside `lab/agent-conformance/`. The branch/worktree
inventory was refreshed at handoff. Cached upstream divergence was zero
commits ahead and nine behind; this offline builder made zero network
requests and zero Git mutations. The supervisor owns the remote refresh,
base compatibility, commit, review and publication.


## 026 — Cancel one pending instance; sibling completes

026: Added cancellation in the existing controller/read journey, cached the two instance builds per test process, checked cancel evidence and receipt identities, exercised live cleanup wiring, and measured the Unix-socket census limit.

The builder read task 026, the supplied 023/backlog handoff, the landed 023
code and LOG record, and the named read-only Runtime seams. The queue itself
is outside this repository and stayed outside the file reads. This repository
has no humanizer skill; this record uses direct statements of behavior and
ownership. All source edits stay inside this lane. Git refs, the index, dependencies
and the probe source remain unchanged.

`Controller::poll` uses the existing first overlap barrier: two pending first
reads in distinct sessions, with both clients alive. In that decision pass,
instance-2 gets its own session grant and instance-1 gets the fixed cancel
reason. The same collector starts each client once and observes later pending
requests until both clients exit. The expected instance-2 sibling read is the
sole later request allowed for instance-1's resource. This resolves the task's
wording about that resource against its required sibling read; every request
from the cancelled session is refused by the harness.

`instance_read_result` checks the sibling first, then requires instance-1's
nonzero exit and the exact delivered denial status/reason. A checked
`cancel settlement:` line records local labels, statuses, the reason and
measured times. Captures, printed lines, report, receipt and candidate/committed
lane sources use the existing credential checker. Missing cancel evidence uses
the existing fixed evidence refusal. The report changes add only the row label
and its two launched-identity requirements; its grader and lab CID parser keep
their behavior.

The completed journey takes the existing live pending/grant census before
operator stop. `check_cleanup_wiring` also plants one shell-owned request,
requires the same caller's census to refuse it, denies that control and repeats
the empty-pending check. The control has zero granted allowance. The ordinary
journey counters retain their original meaning. Cross-session live grants
stay `BLOCKED(AC-021-GRANTS)`.

### Unix socket control and permitted scope fallback

`cleanup_census_refuses_each_leftover` starts a bounded Python child through
`ThrowawayHome::start`, the existing spawn site. It binds `cleanup.sock` in
its in-root cwd, signals readiness by a file and holds the socket for at most
20 seconds. A relative socket path is needed because the absolute worktree
path exceeds macOS's Unix-address limit. The child is stopped before checking
the captured census result, and both control files are removed.

The first discovery run failed its socket-reason assertion:

```text
test cleanup_census_refuses_each_leftover ... FAILED
process leftover; processes:1 paths:["home", "stderr-10", "stdout-10"] API sockets:0 temp:0 paths:[]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.09s
```

The current `lsof +D` census omits this bound Unix socket. Per acceptance 4,
GAPS.md now limits the claim to selected file/directory handles, the API port
and tmp entries. Unix socket absence is unmeasured. The retained control
checks the process refusal and explicitly checks the observed omission, so a
change in visibility requests a scope review. The original API, temp, process
and final-empty assertions remain. The physical census source retains its
original bytes. The narrowed control passed in 3.180 seconds including Cargo;
this is zero proof of Unix-socket absence. Resident cancellation remains RT4.

### Falsifiers run by hand

All commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, the lane-local `target/host` and `target/host-build`,
and the existing shared exclusive heavy-build lease. The first acquisition
waited for another owner; no build overlapped it. The volume had 49.01 GiB
free, above the 12 GiB build estimate plus 2 GiB reserve. Local fixture loopback
and process inspection access were enabled. Every command kept a 600-second
limit. The per-command times below include Cargo. Each edit used the exact
JSON anchor and was restored byte for byte in `finally` before the restored
run. Proof files under `target/task-026-current/` are local and uncommitted.

Each command was:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test <effects-or-report> <named-test> -- --exact --show-output
```

F-cleanup-live-wiring replaces the actual `controller.cleanup_state()` call in
`exercise_read` with a fixed success. Its shell control remains pending at the
call. The test fails with `live cleanup wiring accepted a planted pending
request`, then the fixture settles the control before operator cleanup.
F-cancel-sibling fails on the sibling check, as required. Both are **CAUGHT**.
The three additional new falsifiers cover post-cancel requests, the delivered
reason and both receipt identities. F-instance-receipt's anchor was updated
for the expanded identity arm, and the two retained controls below were rerun.
Each falsifier has one named test, and every named test failed when planted.

F-cancel-sibling — **CAUGHT**.

Baseline: exit 0, 12.846 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 12.72s
```
Planted: exit 101, 13.065 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 11.48s
instance read acceptance failed: "sibling check: instance-2 must finish its own read and receive its sibling denial"
```
Restored: exit 0, 14.278 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 12.93s
```

F-cleanup-live-wiring — **CAUGHT**.

Baseline: exit 0, 11.528 seconds.

```text
test granted_read_succeeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 10.68s
```
Planted: exit 101, 11.189 seconds.

```text
test granted_read_succeeds ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 10.06s
cleanup grant census failed; see checked reason
```
Restored: exit 0, 10.787 seconds.

```text
test granted_read_succeeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 10.06s
```

F-cancel-retry — **CAUGHT**.

Baseline: exit 0, 1.036 seconds.

```text
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.00s
```
Planted: exit 101, 1.685 seconds.

```text
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.00s
assertion `left == right` failed
  left: Ok(true)
 right: Err("cancel: cancelled instance made a further request")
```
Restored: exit 0, 0.617 seconds.

```text
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.00s
```

F-cancel-reason — **CAUGHT**.

Baseline: exit 0, 11.909 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 10.93s
```
Planted: exit 101, 12.179 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 11.21s
instance read acceptance failed: "instance-1 must receive its exact denial status and reason"
```
Restored: exit 0, 20.599 seconds.

```text
test cancelled_instance_settles_with_reason_sibling_completes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 14.62s
```

F-cancel-receipt — **CAUGHT**.

Baseline: exit 0, 1.467 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```
Planted: exit 101, 1.207 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
each launched instance identity is required
```
Restored: exit 0, 1.351 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

F-instance-receipt — **CAUGHT**.

Baseline: exit 0, 0.770 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```
Planted: exit 101, 1.195 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
each launched instance identity is required
```
Restored: exit 0, 1.084 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

F-instance-evidence — **CAUGHT**.

Baseline: exit 0, 1.321 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.00s
```
Planted: exit 101, 1.459 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.03s
assertion `left == right` failed
  left: Err("credential check requires a complete report")
 right: Err("required instance journey evidence is missing")
```
Restored: exit 0, 0.829 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out; finished in 0.00s
```


### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New code/content name or URL where a hash belongs? | No | `tests/effects.rs:169` reuses the existing two builds and `stage_probe`; `src/report.rs:191` requires both launched hash identities. Fixture resource names describe requests, not code identity. |
| 2. New ambient capsule or UI authority? | No | `tests/common/grants.rs:455` makes an explicit fixture decision through the existing Runtime approval route; the capsule and UI sources retain their behavior. |
| 3. Second path or copy of an operation rule? | No | `tests/effects.rs:279` passes the existing cleanup call into its live control; `tests/common/grants.rs:264` continues the same controller after the shared first barrier. |
| 4. Runtime core grows? | No | `tests/common/grants.rs:381` and `tests/effects.rs:537` contain the new lab journey. Every changed path is inside this lane. |
| 5. New refusals fail closed with clear reasons? | Yes | `tests/common/grants.rs:139` fixes the cancel reason; `:264` refuses retries and unexpected requests; `:522` refuses a bypassed cleanup call. |
| 6. Capsule logic stays inside and calls down through granted Bus calls? | Yes | The unchanged `probe/src/lib.rs:138` requests a grant and `:146` invokes the provider; its in-guest byte check still precedes the sibling request. |
| 7. Named tests and caught falsifiers prove the rules? | Yes | `tests/effects.rs:537`, `tests/common/grants.rs:1172`, `tests/report.rs:670` and the five entries beginning at `falsifiers.json:1137` have the baseline/planted/restored results above. Unix socket absence receives zero proof credit. |
| 8. Identity, admission and allowance stay separate? | Yes | `src/report.rs:191` requires identity evidence only; `tests/common/grants.rs:455` still requires explicit per-session grant/deny decisions. The cleanup control receives zero resource allowance. |


### Final author checks and handoff

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`
passed in 0.128 seconds. `bash lab/agent-conformance/run.sh` passed with exit
0 in 234.048 seconds, within the unchanged 600-second bound.
The script ran the complete lane test command:

```sh
cargo test --locked --no-fail-fast --manifest-path lab/agent-conformance/Cargo.toml -- --format pretty --color never --show-output
```

The table has 64 passing tests, zero failed or skipped tests, ten existing
BLOCKED tests, and one passing A14 receipt. Earlier rows retain their grades.
The new row and required regressions read:

```text
attach_secret_stays_in_memory | PASS
cancelled_instance_settles_with_reason_sibling_completes | PASS | cancel at the pending-request point, lab half of A10 (A12 census)
cleanup_census_refuses_each_leftover | PASS
instance_grant_does_not_authorise_sibling | PASS | process-isolation lab half of A3, A6 and A9
run_leaves_no_live_grant | BLOCKED (AC-021-GRANTS) | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included
two_instances_overlap_with_separate_grants | PASS | process-isolation lab half of A3, A6 and A9
```

The same-run receipt is local and uncommitted at
`lab/agent-conformance/target/run-table.y3oHkA/VERSIONS.json`;
its SHA-256 is `aab804c695c31e5d0dbb887bb81be7e4eecd22bb97c14d1a1c68c3ee0beae457`.
It reports complete identity, `cargo_success: true`, `command_success: true`
and `suite_outcome: BLOCKED`. Its source is the uncommitted builder candidate
at HEAD `f15d20535585ac2151840171d9139183ba254026`, with `dirty: true`.
This is author evidence; review and the supervisor's committed-candidate gate
remain separate. The report contains exactly one `cancel settlement:` line:

```text
cancel settlement: instance-1 exit:Some(1) elapsed:0.154009s; instance-2 exit:Some(1) elapsed:0.312288s; reason:fixture cancel: instance-1 cancelled mid-run; first:0.028572s overlap:0.027730s since_cancel:5.552343s; cancel at the pending-request point, lab half of A10 (A12 census)
```

Additional checks passed: `git diff --check`, `bash -n
lab/agent-conformance/run.sh`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
Both Cargo manifests, the lane lockfile, the probe source and physical census
source match HEAD. The new falsifier anchors match once, and earlier anchor
counts remain valid. The F-instance-receipt anchor moved with the identity
arm and passed its new mutation cycle above.

The eight task-owned failed fixture roots were removed after each open-holder
check returned exit 1 with empty output. Their child groups had ended. The
existing `report --check-earlier-runs` then returned exit 0 with empty output.
The shared heavy-build lease is released. The local ignored lifecycle inventory
records the active worktree, removed fixtures, proof directory, receipt and
reusable build caches with supervisor-owned review/removal conditions. Other
owners' roots and worktrees retain their ownership.

The final branch/worktree inventory was refreshed. Cached upstream divergence
was 0 ahead and 10 behind. This offline builder made zero network requests
and zero Git mutations. The supervisor owns remote refresh, base compatibility,
commit, independent review and publication. All ten changed files are inside
`lab/agent-conformance/`.

## 027 — Kill one worker and measure orphan settlement

Added the kill-worker journey through the existing two-instance collector,
overlap decision, controller, settlement formatter and census. The harness
records one SIGKILL and each Home's `run` start count. The absent-policy journey
now measures and settles its pending request after the client wait ends.
All task edits stay in this lane; the probe builds, dependencies and Runtime
sources retain their existing bytes.

Source inspection confirmed `run_cmd.rs:225-269`,
`resource_bridge.rs:1423-1454`, and `capability/pending.rs:16-17` as the relevant
client lifetime, wait and pending-timeout boundaries. The first isolated live
kill run passed in 12.315 seconds, with signal 9, orphan count 1 before and 0
after fixture settlement, a 2.009508-second quiet window, and three passing
root censuses. The earlier sandbox attempt stopped at the loopback bind with
`Operation not permitted`; it is environmental SKIPPED evidence only. The
same test passed with local process and loopback access. Every Cargo run used
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane-owned
build directories, and the shared heavy-build lease. Available disk space was
48.9 GiB, above the documented 12 GiB build allowance plus 2 GiB free.

The checked settlement line uses local labels, exit signal and times. The
fixture carries request IDs and credentials in memory. Its exact orphan denial
is `fixture settlement: worker killed`. The sibling's expected cross-read is
the sole permitted later request for instance-1's resource; every retry from
any session is refused. This interpretation preserves 023's required sibling
outcome. Cleanup keeps live grants `BLOCKED(AC-021-GRANTS)`.

### Falsifier checks

Each entry ran manually in three steps using its exact `falsifiers.json`
edit: baseline, planted, then byte restoration and the same test again.
The command was `cargo test --locked --manifest-path
lab/agent-conformance/Cargo.toml --test <effects|report> <name> -- --exact
--nocapture`. All named tests failed while planted. Local raw results and
measured command times are under ignored `target/task-027/`.

#### F-kill-retry — CAUGHT

Baseline: `killed_worker_settlement_recorded_without_retry`, exit 0, 11.537 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 11.38s
```

Planted: `killed_worker_settlement_recorded_without_retry`, exit 101, 17.814 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 16.01s
overlap journey failed: "no-retry check: instance-1 must start exactly once"
```

Restored: `killed_worker_settlement_recorded_without_retry`, exit 0, 15.251 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 13.85s
```

#### F-kill-sibling — CAUGHT

Baseline: `killed_worker_settlement_recorded_without_retry`, exit 0, 12.136 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 11.18s
```

Planted: `killed_worker_settlement_recorded_without_retry`, exit 101, 12.330 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 11.38s
instance read acceptance failed: "sibling check: instance-2 must finish its own read and receive its sibling denial"
```

Restored: `killed_worker_settlement_recorded_without_retry`, exit 0, 12.639 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 11.70s
```

#### F-kill-record — CAUGHT

Baseline: `killed_worker_settlement_recorded_without_retry`, exit 0, 11.621 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 10.90s
```

Planted: `killed_worker_settlement_recorded_without_retry`, exit 101, 12.383 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 10.92s
required instance settlement evidence: "kill: recorded SIGKILL and signal 9 exit are required"
```

Restored: `killed_worker_settlement_recorded_without_retry`, exit 0, 13.664 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 11.82s
```

#### F-kill-monitor — CAUGHT

Baseline: `grants::tests::kill_refuses_requests_from_any_session`, exit 0, 1.244 seconds.

```text
test grants::tests::kill_refuses_requests_from_any_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.00s
```

Planted: `grants::tests::kill_refuses_requests_from_any_session`, exit 101, 1.052 seconds.

```text
test grants::tests::kill_refuses_requests_from_any_session ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.00s
no-retry check must refuse a worker request from any session
```

Restored: `grants::tests::kill_refuses_requests_from_any_session`, exit 0, 0.876 seconds.

```text
test grants::tests::kill_refuses_requests_from_any_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.00s
```

#### F-orphan-settlement — CAUGHT

Baseline: `killed_worker_settlement_recorded_without_retry`, exit 0, 12.821 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 12.03s
```

Baseline: `no_policy_file_does_not_mean_allow`, exit 0, 37.732 seconds.

```text
test no_policy_file_does_not_mean_allow ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 37.62s
```

Planted: `killed_worker_settlement_recorded_without_retry`, exit 101, 13.992 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 12.35s
instance read acceptance failed: "kill: orphan measurement is missing"
```

Planted: `no_policy_file_does_not_mean_allow`, exit 101, 36.737 seconds.

```text
test no_policy_file_does_not_mean_allow ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 36.60s
cleanup grant census failed; see checked reason
```

Restored: `killed_worker_settlement_recorded_without_retry`, exit 0, 13.757 seconds.

```text
test killed_worker_settlement_recorded_without_retry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 12.58s
```

Restored: `no_policy_file_does_not_mean_allow`, exit 0, 37.662 seconds.

```text
test no_policy_file_does_not_mean_allow ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 37.54s
```

#### F-kill-receipt — CAUGHT

Baseline: `instance_receipt_requires_both_launches_and_scope`, exit 0, 1.044 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

Planted: `instance_receipt_requires_both_launches_and_scope`, exit 101, 1.152 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
each launched instance identity is required
```

Restored: `instance_receipt_requires_both_launches_and_scope`, exit 0, 0.930 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

#### F-instance-evidence — CAUGHT

Baseline: `grants::tests::instance_journey_requires_all_printed_surfaces`, exit 0, 1.093 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.00s
```

Planted: `grants::tests::instance_journey_requires_all_printed_surfaces`, exit 101, 1.037 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.03s
assertion `left == right` failed
  left: Err("credential check requires a complete report")
 right: Err("required instance journey evidence is missing")
```

Restored: `grants::tests::instance_journey_requires_all_printed_surfaces`, exit 0, 0.712 seconds.

```text
test grants::tests::instance_journey_requires_all_printed_surfaces ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 34 filtered out; finished in 0.00s
```

#### F-instance-receipt — CAUGHT

Baseline: `instance_receipt_requires_both_launches_and_scope`, exit 0, 0.728 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s
```

Planted: `instance_receipt_requires_both_launches_and_scope`, exit 101, 1.159 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
each launched instance identity is required
```

Restored: `instance_receipt_requires_both_launches_and_scope`, exit 0, 0.783 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

#### F-cancel-receipt — CAUGHT

Baseline: `instance_receipt_requires_both_launches_and_scope`, exit 0, 0.777 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

Planted: `instance_receipt_requires_both_launches_and_scope`, exit 101, 1.546 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
each launched instance identity is required
```

Restored: `instance_receipt_requires_both_launches_and_scope`, exit 0, 0.788 seconds.

```text
test instance_receipt_requires_both_launches_and_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

#### F-cleanup-report — CAUGHT

Baseline: `cleanup_report_keeps_scope_and_grant_blocker`, exit 0, 0.884 seconds.

```text
test cleanup_report_keeps_scope_and_grant_blocker ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

Planted: `cleanup_report_keeps_scope_and_grant_blocker`, exit 101, 1.047 seconds.

```text
test cleanup_report_keeps_scope_and_grant_blocker ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
assertion failed: text.contains("granted_read_succeeds | PASS | cleanup census, lab half of A10/A11/A12; cancel and kill-worker have separate journey rows")
```

Restored: `cleanup_report_keeps_scope_and_grant_blocker`, exit 0, 0.987 seconds.

```text
test cleanup_report_keeps_scope_and_grant_blocker ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s
```

The moved receipt and cleanup-scope anchors were checked above. The two
older cleanup planting anchors now insert at the shared cleanup call. The
pre-existing F-census-a anchor remains stale on this base; this task leaves
that separate follow-up unchanged. All six new anchors match exactly once.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name or URL where code/content needs a hash? | No | `tests/effects.rs:31` reuses hash-based staging; `src/report.rs:180` requires both launched probe identities for the kill row. |
| 2. New ambient capsule or UI authority? | No | `tests/common/grants.rs:599` retains explicit Runtime grant/deny decisions. All changed paths belong to the lab. |
| 3. Second path or copy of an operation rule? | No | `tests/common/grants.rs:547` owns both orphan settlements; `:426` formats cancel, kill and absent-policy lines; `tests/effects.rs:312` calls the existing census for client roots. |
| 4. Does the trusted Runtime core grow? | No | `src/harness.rs:533` and `tests/common/grants.rs:483` hold the new fixture behavior; Runtime sources retain their bytes. |
| 5. New refusals deny by default with clear reasons? | Yes | `tests/common/grants.rs:289` refuses retries with fixed reasons; `:547` refuses unrelated pending requests and requires an empty list after settlement. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The existing `probe/src/lib.rs:138` requests authority and `:146` invokes the provider. This task adds zero probe code. |
| 7. Named tests and caught falsifiers prove the rules? | Yes | `tests/effects.rs:646`, `tests/common/grants.rs:1421` and `tests/report.rs:670` have the recorded baseline/planted/restored results above. F-orphan-settlement failed both named live tests. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/report.rs:180` checks identity evidence; `tests/common/grants.rs:599` decides each resource request. Killing a worker grants zero resource authority. |

The task changes `ThrowawayHome::spawn` and `RunningInstances::kill_worker`
in `src/harness.rs`; `Controller::poll`, `settle_orphan`, `quiet_after_kill`,
`print_settlement` and their acceptance checks in `tests/common/grants.rs`;
and the shared `exercise_read` journey in `tests/effects.rs`. The existing
report renderer, `run.sh`, RUNBOOK and GAPS add the honest A11/A12 label.
The cleanup, receipt and evidence tests retain their assertions and cover the
new row. The shared physical census and its lsof implementation retain their
code; the kill journey invokes that existing path for each client root.

### Final author gate and retention

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`
passed in 0.107 seconds. `bash lab/agent-conformance/run.sh` passed with exit
0 in 236.852 seconds, within the unchanged 600-second bound. It ran the lane
command with `--locked`, all tests and `--show-output`, using
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. The table has 67 passing tests,
zero failed or skipped tests, ten existing BLOCKED tests, and a passing A14
receipt. Earlier rows keep their grades. The new row reads:

```text
killed_worker_settlement_recorded_without_retry | PASS | kill-worker settlement, lab half of A11 (A12 census); orphan settled by the fixture (AC-027-ORPHAN)
```

The same-run receipt is local and uncommitted at
`target/run-table.i6L2Ex/VERSIONS.json`, with SHA-256
`d16d4244faffc1a272e36f1d92db3dbf82c9bf7337e030a65c7cb21c232ab3b5`.
It reports complete identity, `cargo_success: true`, `command_success: true`
and `suite_outcome: BLOCKED`. It identifies the uncommitted builder candidate
at HEAD `c215763e92c1135421ce1926f8278751758e637a`, with `dirty: true`.
This is author evidence; the supervisor owns the committed-candidate gate and
independent review. The report contains exactly one kill settlement line:

```text
kill settlement: instance-1 exit:None signal:Some(9) elapsed:0.051250s kill_at:0.025964s; instance-2 exit:Some(1) signal:None elapsed:0.318572s kill_at:0.000000s; first:0.025639s overlap:0.024706s since_decision:5.899277s; reason:fixture settlement: worker killed; orphan_before:1 orphan_after:0; settled by the fixture; quiet:2.008535s; kill-worker settlement, lab half of A11 (A12 census)
absent-policy settlement: instance-1 exit:Some(1) signal:None elapsed:30.710404s kill_at:0.000000s; first:0.000000s overlap:0.000000s since_decision:0.000000s; reason:fixture settlement: client wait ended; orphan_before:1 orphan_after:0; settled by the fixture
```

Additional checks passed: `git diff --check`, `bash -n
lab/agent-conformance/run.sh`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
The manifests, lockfile and probe source match HEAD. Every changed path is
inside `lab/agent-conformance/`.

The existing `report --check-earlier-runs` passed after the full gate. Its
root-holder census found zero process holders before removal of the 16
expected-failure and sandbox-refused fixture roots owned by this task.
The local ignored lifecycle inventory records those removals, the proof
folder, receipt, reusable build outputs and active worktree, with supervisor
review/removal conditions. Earlier owners' state stays under their ownership.
The shared heavy-build lease is released. Cached upstream divergence at the
final check was 0 ahead and 13 behind. This builder used offline dependencies
and made zero Git mutations. The supervisor owns remote refresh, base
compatibility, commit, review and publication.

## 028 — real agent-host opt-in: blocked on the launch principal

Added the opt-in target, checked source copy, shared manifest-entrypoint staging,
request-sequence evidence and receipt mapping; the real journey remains FAIL.

### Blocking result

The ready offline operator saw zero pending requests from the real capsule.
`run_component_via_operator_runtime` uses `Runtime::run_local`
(`elastos/crates/elastos-server/src/run_cmd.rs:265`), which passes `None` as
its principal (`elastos/crates/elastos-server/src/runtime.rs:232`). The bridge
requires a principal for `Users/self`
(`elastos/crates/elastos-server/src/resource_bridge.rs:812`) before posting
`/api/capability/request` (`:1388`). The guest handles refused journal grants
inside its activation. This explains the observed `matched:0 granted:0 denied:0`.
The required two shell decisions cannot be measured through this CLI contract.
A task revision or an owner-provided principal-scoped launch contract is needed.
The builder stopped work on dependent acceptance. Runtime and capsule sources
retain their bytes, and the two-request assertion retains its required value.

The sandbox first refused the operator's loopback bind. That pre-launch attempt
was SKIPPED with `operator prerequisite: Operation not permitted (os error 1)`.
The same authorized test then ran with local process/loopback access, under the
shared heavy-build lease, and failed on the real request count. Its operator
census sampled two loopback sockets twice; cleanup reported zero processes,
API sockets and temporary entries. Captures, candidate/committed lane sources,
printed lines, report and receipt passed the existing credential checker.

The targeted command was:

```bash
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml \
  --features agent-host --test agent_host \
  real_agent_host_gets_no_ungranted_authority -- --exact --show-output
```

Its cold component build took 22.122 seconds; the warm component build took
0.722 seconds. The warm test command exited 101 in 12.284 seconds. The source
copy uses only the four listed inputs. The existing relative WIT lookup uses a
copy of the repository Bus contract beside the capsule copy, inside the same
lane-owned throwaway tree. Every build output stays in the lane target.

The existing report produced this table from the warm test binary's exact
Cargo inventory and that run's captured output. This is a targeted failure
table; the requested full `run.sh --agent-host` acceptance run is still open.

```text
test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)
cargo | FAIL
real_agent_host_gets_no_ungranted_authority | FAIL | request sequence: exact request count required | real agent-host capsule, deny half; no model call (RT3)
versions_receipt (A14) | PASS
```

The receipt is local, not committed: `target/task-028/VERSIONS.json`, SHA-256
`3c689a4f5af85eb3a59933977d128aeec71303ab7244af0001f9daa2135051c3`.
Its agent-host identity line is:

```json
{"bundle_lab_cid":"lab-cid:sha256:3c82f41feb51213ae6488d603425b49aeb03ce884269d720b1addde2aba92ec4","component_sha256":"8c961c091669393ab0e8a4bc824726d7a355e0e73cf56e75120ebad6d36f07a4","effect":"agent-host"}
```

This receipt describes a failed test with complete identity, on the uncommitted
candidate based at `8beb8e56266a2403e2723d2024a58a07af078cfa`; it supplies zero
passing journey credit. The source tree at that HEAD is
`0fde0c2ebd182ea6b756a1b0e0475922f16d29ec`.

### Tests and falsifiers

Default-gate additions are `agent_host_copy_takes_only_listed_files`,
`staging_uses_manifest_entrypoint_and_refuses_escape`,
`agent_host_row_requires_its_launched_identity`, and
`grants::request_sequence_requires_exact_order_and_one_session`. They check
source bytes, the allowlist, existing destinations, symlinks, unsafe entrypoints,
missing or build-only identity, failure reasons, ordered request fields and
session/request identity. The opt-in target adds the blocked real journey and
`agent_host_journal_census_detects_planted_paths`.

`F-agent-host-grant` is defined once with `command: lab` and the exact fixture
write grant. It was not applied: the baseline already fails before the fixture
can decide, so a failed mutant would supply zero caught-falsifier evidence.
The requested failing tally/journal assertion, restoration, passing rerun and
all-other-tests-with-mutation checks remain open. The opt-in synthetic journal
census passed when run directly from the same compiled test target. Independent
harness mutations remain unverified. Existing tests
and assertions retain their requirements.

### Principles check (partial candidate)

| Question | Yes/No | Evidence (lane-relative unless stated) |
| --- | --- | --- |
| 1. New name or URL where code/content needs a hash? | No | `src/identity.rs:53` retains checked bundle identity; `src/report.rs:200` requires the launched agent-host effect. |
| 2. New ambient capsule or UI authority? | No | `tests/agent_host.rs:86` uses the committed fixture and the existing guarded launch; the fixture has zero journal grants. |
| 3. Second path or copy of an operation rule? | No | `tests/common/grants.rs:620` remains the poller; `src/identity.rs:53` remains the stager. |
| 4. Does the Runtime core grow? | No | The changed-file inventory contains only `lab/agent-conformance/`; `src/build.rs:18` owns the copied build inputs. |
| 5. New refusals deny by default with clear reasons? | Yes | `src/build.rs:18` names refused paths; `tests/common/grants.rs:708` requires the exact sequence and the report retains the failure reason. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/agent_host.rs:18` builds unchanged guest source; `examples/agent-host/src/lib.rs:3837` still requests its two Bus grants. |
| 7. Named tests and caught falsifiers prove every new rule? | No | The live baseline fails; F-agent-host-grant and independent harness mutations await the revised task contract. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/report.rs:200` checks identity; `tests/agent_host.rs:86` requires separate shell decisions. Complete identity accompanies a FAIL row. |

The local ignored lifecycle inventory is `target/task-028/lifecycle.json`.
It identifies the active worktree, two retained fixture roots, test output and
rebuildable component output. The roots are kept for supervisor review; their
operator is stopped or never launched. Other owners' refs and fixtures stay
under their ownership. This builder performed zero Git mutations or network
operations. The supervisor owns the task decision and any later publication.

### Final author checks and retention

Both requested default gates passed with `RUST_TEST_THREADS=2
CARGO_INCREMENTAL=0` and offline Cargo inputs. `cargo fmt --manifest-path
lab/agent-conformance/Cargo.toml -- --check` exited 0 in 0.106 seconds.
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` exited
0 in 249.162 seconds: 70 passed, zero failed, ten existing ignored tests.
The default Cargo inventory excludes the opt-in target's real journey.
The default gate therefore supplies helper/regression evidence, while the
real-capsule acceptance remains FAIL as recorded above.

Additional checks passed: `git diff --check`, `bash -n
lab/agent-conformance/run.sh`, `node scripts/check-product-data.mjs`
(42 capsules, two profiles, 28 method contracts),
`node --test scripts/check-product-data.test.mjs` (99 passed),
`(cd elastos && cargo fmt --all -- --check)`, and
`cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`.
The lockfile has zero changes. Changed and new source paths are all inside
`lab/agent-conformance/`; the real capsule has zero changes or new untracked
outputs.

The existing `report --check-earlier-runs` passed after the gate. The two
retained task fixture roots have zero process holders. The new 408 MiB
`target/real-agent-host-build` directory was removed after lsof confirmed zero
holders. The local lifecycle inventory records this removal and keeps the
small local receipt and failed-run evidence for supervisor review. The shared
heavy-build lease is released. The cached upstream at final inventory is eight commits ahead of
this branch (local: zero ahead, eight behind); remote refresh remains with the
supervisor because this task permits offline work only.


## 028 — round 2: confirm a root census that saw a capture holder

Review rejected this change. Round 3 removes the confirmation sample, its two
tests and its two falsifiers. The checks below record the rejected candidate
only; they give zero acceptance credit to the restored census.

The shared root census now takes one confirmation sample after an occupied
sample. Cleanup passes only when a complete sample is empty. Every final
holder, including a new holder, still fails the check; either sample's error
keeps its exact reason. `root_holders`, `confirm_holders` and `root_snapshot`
in `src/census.rs` own this rule for both cleanup and the earlier-run check.
The sampler, parser, capture inventory and process exclusions stay shared.
`RUNBOOK.md` and `GAPS.md` state the bound: at most two five-second lsof calls.
The opt-in `Controller::check_requests` method now compiles with its feature,
which removes the default gate's unused-method warning.

The supervisor's saved census showed two handles to one helper capture, held
by one process after the operator group stopped. That PID had exited by this
round's inspection. Its executable identity was unavailable; the capture holder remains unidentified. The confirmation rule
accepts observed release and still rejects persistent holders; it adds zero
process exemptions.

### Named tests and caught falsifiers

- `census::tests::root_census_requires_an_empty_snapshot_after_a_transient_holder`
  requires a second sample for a released holder and exactly one sample when
  the first sample is empty. `F-root-census-no-confirm` was caught with exit
  101 in 6.653 seconds: `released capture needs a fresh empty census`.
- `census::tests::root_census_keeps_persistent_and_new_holders_and_sample_errors`
  checks a persistent holder, a replacement holder, and both exact sample
  errors. `F-root-census-forget-holders` was caught with exit 101 in 0.895
  seconds: `assertion left == right failed: all final holders remain failures`.

Both mutations were applied separately using their exact `falsifiers.json`
edits. Each named test failed. The original source bytes were restored after
each run, and the restored library gate passed (five tests). The existing
`cleanup_census_refuses_each_leftover` and
`cleanup_root_selection_finds_other_groups` then both passed with local
loopback and process inspection available. The first sandbox attempt was
refused at those environment operations and supplies zero Runtime evidence.

### Required gates and task boundary

With `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and all
outputs under the lane target:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.110 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`:
  PASS, exit 0, 273.481 seconds; 72 passed, zero failed, ten existing ignored
  tests. The output contains zero compiler warnings and excludes the opt-in
  real-capsule test. The previously failing sibling-refusal test passes.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml
  --features agent-host --test agent_host
  agent_host_journal_census_detects_planted_paths -- --exact`: PASS, one test.
- `bash -n lab/agent-conformance/run.sh`: PASS. Falsifier IDs are unique and
  both new mutation anchors match exactly once.

Local, uncommitted results are in `target/task-028-round-2/`. The existing
`report --check-earlier-runs` passed after the gate. Its zero-holder result
allowed removal of this round's three sandbox-refused fixture roots. The
local lifecycle inventory records those removals and keeps the small result
folder until supervisor review. Earlier owners' artifacts retain their
ownership. Cargo.lock retains SHA-256
`0142356a31cb18c2564341ba687192c16eb37c4a7ff810c75c379c15052d42c6`.
All direct edits in this round are under `lab/agent-conformance/`; dependency
manifests and lockfiles retain their bytes. This builder issued zero direct Git commands
and made zero external network requests. The required tests retained their
existing read-only identity and source checks. Current remote divergence and the Git diff
inventory remain with the supervisor under the round's Git-command restriction.

Task 028's real-capsule acceptance remains open. The source still routes
`run_local` through `run_local_with_principal(..., None)` at
`elastos/crates/elastos-server/src/runtime.rs:232`, while `Users/self` requires
a principal at `resource_bridge.rs:812`. The earlier live run's zero pending
requests therefore remains the task blocker. The required two-denial assertion
is intact. A principal-scoped launch contract or a revised task is needed;
Runtime changes are outside this lane. The full opt-in table and
F-agent-host-grant passing-baseline/restore proof remain open, as recorded
above. This round grants zero new live agent-host acceptance credit.

### Principles check

| Question | Yes/No | Evidence (lane-relative unless stated) |
| --- | --- | --- |
| 1. New name or URL where code/content needs a hash? | No | `src/identity.rs:79` still checks bundle identity; `src/census.rs:32` inspects process handles only. |
| 2. New ambient capsule or UI authority? | No | `tests/agent_host.rs:148` still requires zero grants and two denials. |
| 3. Second path or copy of an operation rule? | No | `src/census.rs:32` shares one confirmation rule and one snapshot implementation with both callers. |
| 4. Does the Runtime core grow? | No | The repair is in `src/census.rs:42`; Runtime sources were read only. |
| 5. New refusals deny by default with clear reasons? | Yes | `src/census.rs:350` checks final holders and exact propagation of both sample errors. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/agent_host.rs:86` keeps the unchanged real capsule and existing guarded launch. |
| 7. Named tests and caught falsifiers prove every new rule? | No for the full task | The two census tests and mutations above pass their proof cycle; the real-capsule baseline and F-agent-host-grant remain blocked. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/report.rs:202` requires launched identity separately from `tests/agent_host.rs:148`'s grant tally. |

## 028 — round 3: restore the first census result; task remains blocked

Reverted the rejected census retry in `src/census.rs`: `root_holders` again
returns its first snapshot, shared by `cleanup` and `earlier_runs`. Every
observed holder remains a failure. Removed `confirm_holders`, the extracted
`root_snapshot`, their two retry tests, and `F-root-census-no-confirm` and
`F-root-census-forget-holders`. `RUNBOOK.md` and `GAPS.md` again describe one
five-second lsof call. The round-2 record above is marked rejected.

This round adds zero rules, tests or falsifiers. The existing tests and refusal
assertions retain their requirements. In particular,
`cleanup_census_refuses_each_leftover` and
`earlier_run_check_refuses_live_owner` passed. The full default gate failed in
`cleanup_root_selection_finds_other_groups` at `tests/runtime.rs:422`:

```text
assertion failed: root_holders(&first, &roots).unwrap().is_empty()
```

That check follows both test children being stopped. The assertion provides
zero holder-identity evidence; this round gives the result its original FAIL
and adds zero retries or exemptions. The later existing
`report --check-earlier-runs` exited 0 and found zero current holders. That later
observation changes neither the gate result nor the acceptance record. The two
failed fixture roots remain local for supervisor review.

### Checks

Both lane commands ran with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`; Cargo output stayed under the lane target, and the
shared heavy-build lease covered the gate. The volume had more than the
estimated 2 GiB of warm build output plus the required 2 GiB reserve.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.157 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`:
  FAIL, exit 101, 250.137 seconds; 66 passed, one failed, ten ignored before
  Cargo stopped. Later test targets receive zero passing credit.
- `node scripts/check-product-data.mjs`: PASS (42 capsules, two profiles,
  28 method contracts); `node --test scripts/check-product-data.test.mjs`:
  PASS (99 tests).
- `(cd elastos && cargo fmt --all -- --check)` and
  `cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`:
  PASS. `bash -n lab/agent-conformance/run.sh`: PASS.
- Remaining census falsifier anchors and `F-agent-host-grant` match exactly
  once. Falsifier IDs remain unique. This is anchor validation only.

The results and lifecycle inventory are local, uncommitted files under
`target/task-028-round-3/`, retained until supervisor review. The shared lease
is released. Cargo.lock retains SHA-256
`0142356a31cb18c2564341ba687192c16eb37c4a7ff810c75c379c15052d42c6`.
Direct source/document edits stay inside `lab/agent-conformance/`. This round
issued zero direct Git commands or external network requests. The required
suite retained its existing read-only Git identity checks. The supervisor owns
the Git diff inventory and current remote-divergence check under the builder's
Git-command and network restrictions.

### Remaining task gate and owner

Task 028 still needs a principal-scoped launch or a revised task from the
planner. `run_cmd.rs:265` calls `Runtime::run_local`, `runtime.rs:232` supplies
`None`, and `resource_bridge.rs:812` requires a principal for `Users/self`
before a shell request. These are read-only Runtime paths under
`elastos/crates/elastos-server/src/`. The prior live baseline therefore remains
FAIL at `request sequence: exact request count required`.

The real-capsule test retains its two-request assertion and zero-grant tally;
this round adds zero ignored rows. Acceptance 3(a-c), 5 and 6 remains open.
`F-agent-host-grant` awaits a passing baseline, and the full opt-in table awaits
the revised launch/task contract. Re-running the same known-blocked activation
would supply zero new evidence, so this round ran the default gates only.
The supervisor owns the failed cleanup-gate follow-up; the planner owns the
028 task revision. Runtime and principal-contract decisions remain with their
owners outside this lane.

### Principles check

| Question | Yes/No | Evidence (lane-relative unless stated) |
| --- | --- | --- |
| 1. New name or URL where code/content needs a hash? | No | `src/identity.rs:79` retains `checked_bundle`; `src/report.rs:202` requires the launched agent-host identity. |
| 2. New ambient capsule or UI authority? | No | `tests/agent_host.rs:148` retains zero grants and two denials. |
| 3. Second path or copy of an operation rule? | No | `src/census.rs:32` owns the single snapshot used by cleanup and earlier-run checks. |
| 4. Does the Runtime core grow? | No | `src/census.rs:32` is the only Rust implementation changed this round; Runtime source remains read-only. |
| 5. Refusals deny by default with clear reasons? | Yes | `src/census.rs:79` retains cleanup refusal reasons; `tests/runtime.rs:324` still checks each leftover category. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `src/build.rs:18` keeps the checked source copy; this round changes only census handling and its documents. |
| 7. Named tests and caught falsifiers prove every new rule? | No for task 028 | `tests/agent_host.rs:118` still needs the two real requests; `falsifiers.json:1314` awaits a passing baseline. The default gate also failed as recorded above. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/report.rs:202` requires identity separately from `tests/agent_host.rs:148`'s decision tally. |


## 029 — overlap barrier rules caught by planted bugs

Task 029 moves request-shape checks to `barrier_decision`, requires both recorded
barrier decisions in `Controller::check_overlap`, refuses seed `..` segments in
`Fixture::parse`, and labels both instance rows as one shared journey.
`Overlap::ready` retains the time and child-liveness checks. The request rules
have one implementation. The five new tests use synthetic requests; the second
barrier test also checks the controller wiring with bounded system children.
The exited-client test uses `true` and `sleep` through `RunningInstances::start`
and the existing fixed system PATH. Both tests collect the children before
checking the result. The Runtime, probe, dependencies, grader, cancel journey
and kill journey keep their existing source.

### Manual falsifier evidence

Each entry below ran its exact edits separately, with the shared heavy-build
lease held. Every command used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, lane-owned Cargo target/build directories and a
600-second deadline. All new `old` anchors match once in the unmutated candidate;
earlier falsifier anchor counts are unchanged. Source bytes were restored after
each mutation. Every named test failed planted and passed before and after it.
These results describe the working candidate, rather than a committed head.

Command for each named test below:

```sh
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects TEST_NAME -- --exact --show-output
```

### F-overlap-second-barrier — CAUGHT

`grants::tests::overlap_second_barrier_waits_for_both_requests`:

```text
baseline: exit 0, wall 1.160s
test grants::tests::overlap_second_barrier_waits_for_both_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 1.07s
planted: exit 101, wall 2.234s
test grants::tests::overlap_second_barrier_waits_for_both_requests ... FAILED
assertion `left == right` failed: second barrier must wait for both requests
 right: Ok(false)
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 1.06s
restored: exit 0, wall 1.910s
test grants::tests::overlap_second_barrier_waits_for_both_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 1.07s
```

`two_instances_overlap_with_separate_grants`:

```text
baseline: exit 0, wall 13.246s
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 13.12s
planted: exit 101, wall 11.518s
test two_instances_overlap_with_separate_grants ... FAILED
required instance settlement evidence: "overlap: both barriers require two requests from distinct sessions"
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 11.42s
restored: exit 0, wall 11.178s
test two_instances_overlap_with_separate_grants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 11.06s
```

### F-overlap-sessions — CAUGHT

`grants::tests::overlap_barrier_refuses_one_session_for_both`:

```text
baseline: exit 0, wall 0.882s
test grants::tests::overlap_barrier_refuses_one_session_for_both ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
planted: exit 101, wall 1.198s
test grants::tests::overlap_barrier_refuses_one_session_for_both ... FAILED
assertion `left == right` failed
 right: Err("overlap: two distinct client sessions required")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
restored: exit 0, wall 1.002s
test grants::tests::overlap_barrier_refuses_one_session_for_both ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
```

### F-overlap-sibling-new — CAUGHT

`grants::tests::overlap_sibling_read_must_be_new_in_its_session`:

```text
baseline: exit 0, wall 0.783s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
planted: exit 101, wall 1.372s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... FAILED
assertion `left == right` failed: sibling rule must check request_id
 right: Err("overlap: sibling read must be new in its original session")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
restored: exit 0, wall 0.943s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
```

### F-overlap-alive — CAUGHT

`grants::tests::overlap_barrier_refuses_when_a_client_has_exited`:

```text
baseline: exit 0, wall 3.043s
test grants::tests::overlap_barrier_refuses_when_a_client_has_exited ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 2.05s
planted: exit 101, wall 3.286s
test grants::tests::overlap_barrier_refuses_when_a_client_has_exited ... FAILED
assertion `left == right` failed
 right: Err("overlap: both clients must remain alive through both barriers")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 2.04s
restored: exit 0, wall 3.361s
test grants::tests::overlap_barrier_refuses_when_a_client_has_exited ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 2.04s
```

### F-seed-dotdot — CAUGHT

`grants::tests::seed_fixture_refuses_dot_dot`:

```text
baseline: exit 0, wall 0.950s
test grants::tests::seed_fixture_refuses_dot_dot ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
planted: exit 101, wall 1.224s
test grants::tests::seed_fixture_refuses_dot_dot ... FAILED
assertion `left == right` failed
 right: Some("seed fixture refuses a parent-directory segment")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
restored: exit 0, wall 0.948s
test grants::tests::seed_fixture_refuses_dot_dot ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 40 filtered out; finished in 0.00s
```

F-overlap-second-barrier plants exactly
`if self.stage == 1 { return Ok(!pending.is_empty()); }` in `Overlap::ready`.
The live journey now fails with the fixed missing-barrier-evidence reason,
while the synthetic wiring test fails because a lone sibling was accepted.
F-overlap-sibling-new removes the request-ID clause; its test also checks a
changed session, swapped sessions and a wrong resource with the existing reason.
F-overlap-alive removes both `all_alive(2)` observations in `ready`; the test
then gets `Ok(true)` instead of the required both-alive refusal.

### Verification environment

The first restricted run reached 12 passing unit tests and two failures in
process-group inspection (`could not inspect child process group`). The same
14 tests passed with local process inspection allowed, in 2.178 seconds.
This was a sandbox limit. Test assertions and cleanup rules stayed fixed.
The full lane gates use that same local access. The volume had 48.41 GiB free
before builds, above the runbook's 12 GiB estimate plus 2 GiB reserve.
The earlier task-029 proof directory was preserved; this run's local,
uncommitted evidence is under `target/task-029-current/`.

### Principles check

| Question | Yes/No | Evidence (lane-relative) |
| --- | --- | --- |
| 1. New name or URL where code/content needs a hash? | No | `src/identity.rs:79` retains bundle checking; `tests/common/grants.rs:188` checks resource requests, rather than code identity. |
| 2. New ambient capsule or UI authority? | No | `tests/common/grants.rs:225` still requires an exact fixture grant for each own read. |
| 3. Second path or copy of an operation rule? | No | `tests/common/grants.rs:188` owns request-shape validation and `:308` calls it from the existing controller. |
| 4. Does the Runtime core grow? | No | `tests/common/grants.rs:285` is the existing lab controller; implementation edits stay in this test module. |
| 5. Refusals deny by default with clear reasons? | Yes | `tests/common/grants.rs:96` refuses parent segments; `:636` refuses missing barrier evidence with a fixed reason. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `probe/src/lib.rs:138` and `:146` retain the capability request followed by the provider call; probe source is unchanged. |
| 7. Named tests and caught falsifiers prove each new rule? | Yes | `tests/common/grants.rs:1360` through the five named tests and `falsifiers.json:1330` onward have baseline/planted/restored evidence above; both second-barrier tests failed. |
| 8. Identity, admission and allowance remain separate? | Yes | `src/identity.rs:79` owns bundle identity, `tests/common/grants.rs:225` checks grants, and `:300` retains the time bound. |

### Final gates and handoff

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.175 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`:
  PASS, exit 0, 258.287 seconds within the unchanged 600-second
  bound; 75 passed, 0 failed, 10 ignored with their existing blockers.
  Both instance rows, the cancel/kill rows and the earlier active rows passed.
- `git diff --check`, `bash -n lab/agent-conformance/run.sh`,
  `node scripts/check-product-data.mjs` (42 capsules, two profiles,
  28 method contracts), `node --test scripts/check-product-data.test.mjs`
  (99 passed), `(cd elastos && cargo fmt --all -- --check)` and
  `cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`:
  PASS. The workspace formatting check ran from `elastos/`.
- All five new mutation anchors are restored and unique. Falsifier IDs are
  unique, and earlier anchor counts retain their pre-task values.
  Cargo.toml and Cargo.lock match HEAD byte for byte.

The shared heavy-build lease is released. The local lifecycle inventory at
`target/task-029-current/lifecycle.json` records this task worktree, proof files
and seven retained expected-failure/sandbox roots. Their test processes have
ended; the supervisor owns review and removal of retained test data. The
existing build cache remains lane-owned reproducible state. Earlier task-029
proof was preserved separately. Branch/worktree metadata was inspected with
read-only Git commands. The candidate has six changed lane files. Cached
`spike/spike/agent-host` is six commits ahead of the local task branch; this run
performed zero fetches or Git-state changes. The supervisor owns the next
review, current-base compatibility check and publication.

## 029 — round 2: preserve the cleanup failure; gate blocked by build lease

029 round 2: Rechecked the candidate and recorded the supervisor's cleanup
failure; the full test rerun waits for the shared heavy-build lease.

The supervisor's required test command exited 101. Its effects target reported
31 passed, one failed and nine ignored in 208.04 seconds. The failed test was
`cancelled_instance_settles_with_reason_sibling_completes`. Both clients exited,
then the cleanup census reported one process holding
`home/Library/Application Support/elastos/host-process.lock`, zero API sockets,
zero temporary entries and zero pending requests. The assertion was:

```text
test cancelled_instance_settles_with_reason_sibling_completes ... FAILED
cleanup census refused leftovers; see checked reason
test result: FAILED. 31 passed; 1 failed; 9 ignored; 0 measured; 0 filtered out; finished in 208.04s
```

The earlier lane records include cleanup-census failures after collection
(022 and 028). This result is consistent with that intermittent failure class;
its cause remains unproven. Task 029 acceptance 7 directs the builder to report
a known flake and preserve its code. The cancel journey and cleanup assertions
therefore retain their existing requirements. The failed supervisor run remains
FAIL; the earlier passing gate is separate evidence.

All six task files matched the saved SHA-256 values from this candidate's
previous verification before this log append. The five new falsifiers retain
unique, restored anchors and unique IDs. Their recorded baseline/planted/restored
results above still describe the current Rust source and falsifier definitions;
this round adds zero rules, tests or falsifiers and repeats zero mutation runs.
Cargo.toml and Cargo.lock also retain their pre-round bytes.

### Round-2 checks

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.045 seconds, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
  CARGO_NET_OFFLINE=true`.
- The full `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`
  rerun is NOT RUN. The first exclusive lease attempt was busy; a subsequent
  bounded wait remained busy for 180 seconds and exited 3 before starting Cargo
  or test children. Each gate command retains its 600-second deadline. The
  volume had 48.38 GiB free, above the 12 GiB build estimate plus 2 GiB reserve.
- `bash -n lab/agent-conformance/run.sh`: PASS.
- `node scripts/check-product-data.mjs`: PASS (42 capsules, two profiles,
  28 method contracts); `node --test scripts/check-product-data.test.mjs`:
  PASS (99 tests).
- `(cd elastos && cargo fmt --all -- --check)` and
  `cargo fmt --manifest-path capsules/chain-provider/Cargo.toml -- --check`:
  PASS.

Local round-2 evidence and its lifecycle inventory are under
`target/task-029-round-2/`, retained until supervisor review. This round acquired
zero build leases and started zero fixture Homes. Existing retained roots stay
with their recorded owners. Git state is unchanged; the cached upstream is six
commits ahead, and current remote state needs the supervisor's permitted check.
The supervisor owns the next full gate when the build lease is free, followed
by review and publication. Task acceptance remains open until that gate passes.
The eight principles answers and file-line evidence above remain applicable.

## 029 — round 3: unchanged candidate passes the full gate

029 round 3: Preserved the supervisor's cleanup-census failure and reran the
unchanged candidate under the shared heavy-build lease; the full locked gate passed.

The supervisor run failed in
`process_isolation::parallel_instances_complete_independently`. Its final
census reported one process holding
`home/Library/Application Support/elastos/host-process.lock`, zero API sockets
and zero temporary entries. Its effects target reported:

```text
test process_isolation::parallel_instances_complete_independently ... FAILED
final census and operator group stop: "cleanup census: FAIL retained:target/home-68129-1793019599652132000-152; process leftover; processes:1 paths:[\"home/Library/Application Support/elastos/host-process.lock\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)"
test result: FAILED. 31 passed; 1 failed; 9 ignored; 0 measured; 0 filtered out; finished in 183.64s
```

This matches the previously recorded intermittent cleanup-failure class; its
cause remains unproven. Acceptance item 7 directs the builder to preserve the
code for a known flake and report it. This round changes this log only. The
controller, cleanup paths, assertions, dependencies and earlier row grades
retain their requirements. The failed supervisor run remains separate evidence.

### Round-3 checks

Both lane commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, the runbook's lane-local target directories and the
unchanged 600-second deadline. The volume had 48.25 GiB free before the gate,
above the 12 GiB build estimate plus 2 GiB reserve. The existing shared lease
was acquired for the test command and released after it completed.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.120 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`:
  PASS, exit 0, 248.300 seconds; 75 passed, zero failed, ten ignored with their
  existing blockers. The effects target passed in 191.42 seconds:

```text
test process_isolation::parallel_instances_complete_independently ... ok
test two_instances_overlap_with_separate_grants ... ok
test instance_grant_does_not_authorise_sibling ... ok
test result: ok. 32 passed; 0 failed; 9 ignored; 0 measured; 0 filtered out; finished in 191.42s
```

- All five task-029 named tests passed. Their source and the five falsifier
  definitions match the earlier verified SHA-256 values. Each restored edit
  anchor occurs exactly once, and falsifier IDs remain unique. The recorded
  baseline/planted/restored runs still cover these exact bytes; this round
  adds zero tests or falsifiers and repeats zero mutation runs.
- `bash -n lab/agent-conformance/run.sh`, product-data validation (42 capsules,
  two profiles, 28 method contracts), its 99 Node tests, Runtime formatting
  from `elastos/`, and chain-provider formatting: PASS.
- Cargo.toml and Cargo.lock retain their pre-round bytes. The builder ran zero
  Git commands; remote divergence was therefore left for the supervisor to
  check before publication.

Local evidence and its lifecycle inventory are in
`target/task-029-round-3/`, retained until supervisor review. The gate left zero
new retained test Homes. Earlier retained roots remain with their recorded
owners. The eight principles answers and file-line evidence above still apply
to the unchanged implementation. The repository has no humanizer skill; this
record uses direct statements of behavior and ownership. The supervisor owns
review and publication.


## 034 — BLOCKED rows require matching GAPS evidence

034: The existing report grader now checks each BLOCKED row against one matching
`GAPS.md` row, and rejects stale passing rows with fixed reasons.

`src/bin/report.rs::main` reads `build::lane()/GAPS.md` and passes its text into
`write_run`, `render_run` and the existing `Evidence::parse` path. Cargo still
owns the test inventory and results. The parser selects only backticked names
from that inventory. `grade` and `check_blocked_gap` require exactly one row,
the same trimmed semicolon-separated ID set, and a nonempty Runtime-change
cell. Failures name the test and the missing or extra IDs in the table and
report failures. A passing test with a GAPS row fails as stale evidence.
An unreadable file fails with `could not read GAPS.md`.

The report tests keep their existing assertions and receive explicit GAPS
inputs. `tests/common/grants.rs::report_inventory` supplies the lane document
to that same grader. `GAPS.md` gains the three missing rows for bundle-CID
launch, resource-stop reasons and cross-session live-grant visibility.
`RUNBOOK.md` describes the new requirement in two lines. The existing cancel
and kill-worker scope label stays intact.

Six new synthetic tests cover this rule:
`blocked_row_needs_gaps_row` (also duplicate rows and unrelated table rows),
`blocked_row_ids_must_match_gaps` (different, missing, extra and empty IDs),
`blocked_row_needs_runtime_change`, `gaps_listed_test_that_passes_fails`,
`blocked_row_accepts_reordered_ids_and_ignores_other_rows` (set order,
duplicate IDs and inventory filtering), and `unreadable_gaps_fails_the_run`.

### Hand-run falsifiers

The falsifiers stay out of `falsifiers.json` because the runner's `lab` command runs `lab/wasm-capsule`, so a new ID here reads NOT RUN; move them into the list when this lane has its own runner command (BACKLOG item 7).

Each harness test used `cargo test --locked --manifest-path
lab/agent-conformance/Cargo.toml --test report TEST -- --exact --nocapture`.
Each named test passed before the edit, failed with the edit, and passed after
restoration. Every named test failed for F-gaps-any-reason, including the
Runtime-change test. The extra F-gaps-unreadable proves the missing-input
refusal. The fixture falsifier ran the real `./run.sh` for all three steps.
JSON strings in the old/new columns specify the exact replacement bytes;
`\n` denotes one newline and `""` denotes deletion.

| ID | File (relative to lane) | Exact old text | Exact new text | Named tests / command | Libtest lines and results | Failing assertion or report refusal |
| --- | --- | --- | --- | --- | --- | --- |
| F-gaps-any-reason | <code>src/report.rs</code> | <code>&quot;            check_blocked_gap(name, reason, gaps)?;&quot;</code> | <code>&quot;            // Accept any non-empty blocker reason.&quot;</code> | <code>blocked_row_needs_gaps_row</code><br><code>blocked_row_ids_must_match_gaps</code><br><code>blocked_row_needs_runtime_change</code> | baseline: <code>test blocked_row_needs_gaps_row ... ok</code> (exit 0, 0.794 s)<br>baseline: <code>test blocked_row_ids_must_match_gaps ... ok</code> (exit 0, 0.089 s)<br>baseline: <code>test blocked_row_needs_runtime_change ... ok</code> (exit 0, 0.090 s)<br>planted: <code>test blocked_row_needs_gaps_row ... FAILED</code> (exit 101, 1.083 s)<br>planted: <code>test blocked_row_ids_must_match_gaps ... FAILED</code> (exit 101, 0.093 s)<br>planted: <code>test blocked_row_needs_runtime_change ... FAILED</code> (exit 101, 0.086 s)<br>restored: <code>test blocked_row_needs_gaps_row ... ok</code> (exit 0, 0.831 s)<br>restored: <code>test blocked_row_ids_must_match_gaps ... ok</code> (exit 0, 0.091 s)<br>restored: <code>test blocked_row_needs_runtime_change ... ok</code> (exit 0, 0.086 s) | <code>tests/report.rs:173: assert!(!report.passed, &quot;GAPS mismatch must fail the run&quot;)</code> |
| F-gaps-stale-pass | <code>src/report.rs</code> | <code>&quot;        if !gaps.is_empty() {&quot;</code> | <code>&quot;        if false &amp;&amp; !gaps.is_empty() {&quot;</code> | <code>gaps_listed_test_that_passes_fails</code> | baseline: <code>test gaps_listed_test_that_passes_fails ... ok</code> (exit 0, 0.785 s)<br>planted: <code>test gaps_listed_test_that_passes_fails ... FAILED</code> (exit 101, 1.060 s)<br>restored: <code>test gaps_listed_test_that_passes_fails ... ok</code> (exit 0, 0.844 s) | <code>tests/report.rs:173: assert!(!report.passed, &quot;GAPS mismatch must fail the run&quot;)</code> |
| F-gaps-row | <code>GAPS.md</code> | <code>&quot;&#124; `ungranted_model_call_is_refused` &#124; RT3 &#124; Anders supplies the component model-call grant contract and its refusal path. &#124;\n&quot;</code> | <code>&quot;&quot;</code> | <code>ungranted_model_call_is_refused (report row; ./run.sh)</code> | Planted libtest: <code>test ungranted_model_call_is_refused ... ignored, blocked: RT3</code><br>baseline: exit 0, 214.080 s; <code>ungranted_model_call_is_refused &#124; BLOCKED (RT3)</code><br>planted: exit 1, 220.407 s; <code>ungranted_model_call_is_refused &#124; FAIL &#124; GAPS.md: ungranted_model_call_is_refused: missing row for blocker IDs: RT3</code><br>restored: exit 0, 216.941 s; <code>ungranted_model_call_is_refused &#124; BLOCKED (RT3)</code><br> | The report requires a matching row and returns exit 1: <code>GAPS.md: ungranted_model_call_is_refused: missing row for blocker IDs: RT3</code>. Cargo tests themselves passed. |
| F-gaps-unreadable | <code>src/report.rs</code> | <code>&quot;        let mut evidence = Self::default();&quot;</code> | <code>&quot;        let gaps = gaps.or(Some(\&quot;\&quot;));\n        let mut evidence = Self::default();&quot;</code> | <code>unreadable_gaps_fails_the_run</code> | baseline: <code>test unreadable_gaps_fails_the_run ... ok</code> (exit 0, 0.803 s)<br>planted: <code>test unreadable_gaps_fails_the_run ... FAILED</code> (exit 101, 1.028 s)<br>restored: <code>test unreadable_gaps_fails_the_run ... ok</code> (exit 0, 0.808 s) | <code>tests/report.rs:272: assertion failed: !report.passed</code> |

All four edits are restored and each old-text anchor occurs exactly once.
Existing report falsifier anchor counts retain their base values.

### Real table and gates

Both successful `run.sh` runs reported these ten ignored rows, with zero FAIL
rows. The baseline exited 0 in 214.080 seconds; the restored run exited 0 in
216.941 seconds. Their receipts record `suite_outcome: BLOCKED` and
`command_success: true`. The planted run exited 1 in 220.407 seconds and
recorded `suite_outcome: FAIL` with the one missing-row failure above.

```text
agent_can_read_human_space_with_grant | BLOCKED (UsersAI binding; AC-002-ARGS)
agent_cannot_read_other_agent_memory | BLOCKED (UsersAI binding; AC-002-ARGS)
agent_memory_under_own_principal | BLOCKED (UsersAI binding; AC-002-ARGS)
capsule_named_by_hash | BLOCKED (AC-025-CID)
operator_storage_is_under_throwaway_home | BLOCKED (AC-006-STORAGE)
parallel_capsules_complete_independently | BLOCKED (RT4)
parallel_instances_return_success_payloads | BLOCKED (AC-002-ARGS)
process_isolation::runaway_is_stopped_with_reason | BLOCKED (AC-005-REASON)
run_leaves_no_live_grant | BLOCKED (AC-021-GRANTS) | cleanup census, lab half of A10/A11/A12; cancel and kill-worker have separate journey rows
ungranted_model_call_is_refused | BLOCKED (RT3)
```

All lane runs used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, lane-local `target/host` and `target/host-build`, and
the shared heavy-build lease. Each gate retained its 600-second deadline.
The volume had 46 GiB free before builds, above the 12 GiB estimate plus the
2 GiB reserve. The final commands passed:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  exit 0, 0.140 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`:
  exit 0, 217.495 seconds; 81 passed, zero failed, ten ignored. The report
  target passed all 18 tests. The kill-worker test passed on all three host
  `run.sh` runs and on this gate.
- `git diff --check`, `bash -n lab/agent-conformance/run.sh`, product-data
  validation (42 capsules, two profiles, 28 method contracts), its 99 Node
  tests, Runtime formatting from `elastos/`, and chain-provider formatting:
  PASS. These checks changed zero files outside the lane.

The first sandboxed `run.sh` attempt exited 1 in 58.502 seconds because the
sandbox refused loopback setup (`Operation not permitted`) and process-group
inspection (`could not inspect child process group`). That attempt supplies
zero live journey acceptance. The unchanged candidate then passed with the
host access required by these isolated fixtures. The known kill-worker
cleanup flake did not occur on the host runs; its code and assertions retain
their base behavior.

`Cargo.toml`, `Cargo.lock`, `falsifiers.json` and `run.sh` match the base bytes.
The evidence is local and uncommitted under `target/task-034/`; receipt paths
and SHA-256 values are in its `receipts.json`. The receipts identify the base
commit with a dirty candidate, rather than a committed task change. The local
lifecycle inventory records this worktree, proof and retained test roots;
the supervisor owns review and their cleanup decision. The shared build
lease is released. The repository has no humanizer skill source; this record
uses direct statements of behavior and ownership.

### Principles check

Paths below are relative to `lab/agent-conformance/`.

| Question | Answer | Evidence |
| --- | --- | --- |
| 1. New name or URL where a code/content hash belongs? | No | `src/bin/report.rs:39` reads test metadata; `src/identity.rs:79` retains checked bundle identity. |
| 2. Capsule, Home or UI gains ambient authority? | No | `src/report.rs:37` checks report evidence; `src/harness.rs:220` retains the cleared launch environment. |
| 3. A second path or rule copy for one operation? | No | `src/report.rs:92` extends the existing inventory parser; `src/report.rs:20` remains the single grading rule. |
| 4. Runtime core grows? | No | `src/report.rs:37` keeps the change in the lab report; Runtime and provider sources retain their base bytes. |
| 5. New refusals deny by default with clear reasons? | Yes | `src/report.rs:37` refuses missing, duplicate, differing or incomplete rows; `src/report.rs:20` refuses stale passing rows. |
| 6. Capsule logic stays inside and calls through granted Bus operations? | Yes | `probe/src/lib.rs:138` requests the grant before the provider call at line 146; the probe is unchanged. |
| 7. Named tests and caught falsifiers prove the rules? | Yes | `tests/report.rs:183` through `:270` supply synthetic checks; the table above records every named test failing planted and passing restored. |
| 8. Identity, admission and allowance stay separate? | Yes | `src/report.rs:518` retains the receipt's separate identity, admission and Runtime-grant statement; this change grades blocker evidence only. |

Final handoff check: `target/host/debug/report --check-earlier-runs` exited 0;
all test Home processes have ended. The ledger keeps 51 new retained test
roots (27,982,568 bytes) for supervisor review, with removal when that review
ends. Seven changed files are confined to this lane. The current branch is
zero commits ahead and zero behind its cached `spike/spike/agent-host` ref;
remote state was not fetched. The builder made zero Git-state changes. The
supervisor owns review, publication and the recorded cleanup decisions.


## 035 — Kill row requires measured fixture settlement

035: `Settlement::check` now requires one measured orphan and zero after settlement for both journeys; `matches_orphan` gives changed pending requests their own fixed refusal.

The kill journey calls the shared check in `Controller::check_kill`; the
absent-policy journey calls it in `exercise_read`. A zero count gives
`orphan already settled when measured; re-measure AC-027-ORPHAN and name the Runtime source line`.
More than one request retains the existing unexpected-request refusal.
`Settlement::line` prints both counts and adds `settled by the fixture` only
when this same check passes. The report label stays unchanged.

`matches_orphan` checks request and session identity and refuses any changed
field under the original request ID with `orphan request changed while pending`.
`poll`, `settle_orphan` and `observe_unapproved` use this one helper. New
request IDs still reach the existing unexpected-request or retry checks.
The existing cancellation and kill retry tests retain all their assertions.
`GAPS.md` and `RUNBOOK.md` describe the required re-measurement when Runtime
closes AC-027-ORPHAN.

### Hand-run falsifiers

There is no new list ID because the runner's `lab` command runs `lab/wasm-capsule`; BACKLOG item 7 owns the later list rewrite.

Both new tests run under the effects target with
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects grants::tests::TEST -- --exact --nocapture`.
Every run used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`,
lane-local host/build directories and the shared heavy-build lease.
JSON strings below specify exact replacement bytes; `\n` is one newline.
Each mutation was restored before the next run. Every named test failed
with its planted bug and passed both before and after it.

| ID | File (relative to lane) | Exact old text | Exact new text | Named test | Libtest lines and results | Failing assertion |
| --- | --- | --- | --- | --- | --- | --- |
| F-orphan-owner | <code>tests/common/grants.rs</code> | <code>&quot;        if self.before == 0 {\n            return Err(\&quot;orphan already settled when measured; re-measure AC-027-ORPHAN and name the Runtime source line\&quot;);\n        }\n        if self.before != 1 {&quot;</code> | <code>&quot;        if self.before &gt; 1 {&quot;</code> | <code>grants::tests::kill_requires_measured_fixture_settlement</code> | baseline: <code>test grants::tests::kill_requires_measured_fixture_settlement ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 0, 1.604 s)<br>planted: <code>test grants::tests::kill_requires_measured_fixture_settlement ... FAILED / test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 101, 0.934 s)<br>restored: <code>test grants::tests::kill_requires_measured_fixture_settlement ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 0, 0.712 s) | <code>assertion `left == right` failed: kill requires exactly one measured orphan and zero after settlement;   left: Ok(());  right: Err(&quot;orphan already settled when measured; re-measure AC-027-ORPHAN and name the Runtime source line&quot;)</code> |
| F-orphan-match | <code>tests/common/grants.rs</code> | <code>&quot;    let same_id = field(request, \&quot;request_id\&quot;)? == field(original, \&quot;request_id\&quot;)?;\n    if same_id &amp;&amp; request != original {\n        return Err(\&quot;orphan request changed while pending\&quot;);\n    }\n    Ok(same_id &amp;&amp; field(request, \&quot;session_id\&quot;)? == field(original, \&quot;session_id\&quot;)?)&quot;</code> | <code>&quot;    Ok(field(request, \&quot;request_id\&quot;)? == field(original, \&quot;request_id\&quot;)?)&quot;</code> | <code>grants::tests::changed_orphan_has_its_own_reason</code> | baseline: <code>test grants::tests::changed_orphan_has_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 0, 0.076 s)<br>planted: <code>test grants::tests::changed_orphan_has_its_own_reason ... FAILED / test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 101, 0.977 s)<br>restored: <code>test grants::tests::changed_orphan_has_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.00s</code> (exit 0, 0.784 s) | <code>assertion `left == right` failed: a changed orphan needs its own reason;   left: Ok(true);  right: Err(&quot;orphan request changed while pending&quot;)</code> |

`kill_requires_measured_fixture_settlement` exercises `Controller::check_kill`
with before/after pairs 0/0, 1/0, 2/0 and 1/1. It checks the fixed refusal or
success and the exact printed counts/owner suffix. `changed_orphan_has_its_own_reason`
checks an unchanged orphan, a different request ID, changed session/resource/
action/reason fields, an added field and a removed session field.

All existing list anchors retain their base match counts. F-cancel-retry,
F-kill-retry, F-kill-monitor and F-orphan-settlement still each match once;
this task moved none of their replacement text. Thus there is no stale anchor
from 035 to re-run or carry to BACKLOG item 7. The exact two mutations above
remain ready for that list rewrite. `falsifiers.json` retains its base bytes.

### Principles check

Paths below are relative to `lab/agent-conformance/`.

| Question | Answer | Evidence |
| --- | --- | --- |
| 1. New name or URL where a code/content hash belongs? | No | `src/identity.rs:91` retains the checked bundle CID; `tests/common/grants.rs:199` matches pending request identity only. |
| 2. Capsule, Home or UI gains ambient authority? | No | `probe/src/lib.rs:138` retains the Runtime grant request before the provider call; this task changes fixture checks. |
| 3. A second path or rule copy for one operation? | No | `tests/common/grants.rs:172` owns the count rule used by `check_kill` and `tests/effects.rs:518`; `tests/common/grants.rs:199` owns orphan matching for all three callers. |
| 4. Runtime core grows? | No | `tests/common/grants.rs:172` keeps the change in the lab harness; Runtime, provider and probe sources retain their base bytes. |
| 5. New refusals fail closed with clear reasons? | Yes | `tests/common/grants.rs:172` rejects absent, excess and remaining orphans; line 199 rejects changed requests with a fixed reason. |
| 6. Capsule logic stays inside and calls through granted Bus operations? | Yes | `probe/src/lib.rs:138` requests the grant and line 146 passes it to the provider; this path retains its base bytes. |
| 7. Named tests and caught falsifiers prove each rule? | Yes | `tests/common/grants.rs:1683` and `:1733` are the two named tests; both fail planted and pass restored in the table above. |
| 8. Identity, admission and allowance remain separate decisions? | Yes | `src/report.rs:518` retains the separate identity, admission and session-grant statement; settlement counts grant zero authority. |

The repository has no humanizer skill source. This record uses direct
statements of behavior and ownership. The supervisor owns review and
publication; the builder changes only this lane's files.

### Real journeys and gates

The full locked lane run exercised both real journeys once. Their checked
lines below come from their own libtest stdout sections, separate from the
synthetic count test's output:

```text
test killed_worker_settlement_recorded_without_retry ... ok
kill settlement: instance-1 exit:None signal:Some(9) elapsed:0.055394s kill_at:0.027729s; instance-2 exit:Some(1) signal:None elapsed:0.306679s kill_at:0.000000s; first:0.027348s overlap:0.026489s since_decision:5.874556s; reason:fixture settlement: worker killed; orphan_before:1 orphan_after:0; settled by the fixture; quiet:2.002440s; kill-worker settlement, lab half of A11 (A12 census)
test no_policy_file_does_not_mean_allow ... ok
absent-policy settlement: instance-1 exit:Some(1) signal:None elapsed:30.706156s kill_at:0.000000s; first:0.000000s overlap:0.000000s since_decision:0.000000s; reason:fixture settlement: client wait ended; orphan_before:1 orphan_after:0; settled by the fixture
```

The gate used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`,
lane-local `target/host` and `target/host-build`, and the shared heavy-build
lease. The volume had 45.93 GiB free before builds,
above the 12 GiB estimate plus 2 GiB reserve. Each gate had a 600-second limit.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  PASS, exit 0, 0.285 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml -- --show-output`:
  PASS, exit 0, 230.162 seconds; 83 passed, zero failed,
  ten ignored with their existing blockers. The effects target passed all
  34 active tests in 181.76 seconds; nine retained their blockers.
- `git diff --check`, product-data validation (42 capsules, two profiles,
  28 method contracts), its 99 Node tests, Runtime formatting from `elastos/`,
  chain-provider formatting and `bash -n lab/agent-conformance/run.sh`: PASS.

The first sandboxed gate exited 101 in 1.626 seconds:
`earlier_run_check_refuses_live_owner` failed with
`could not inspect child process group`, before either live journey ran.
The unchanged suite passed with host process inspection and loopback access.
The known kill-worker cleanup flake did not occur; its code and assertions
retain their base behavior.

`Cargo.toml`, `Cargo.lock`, `falsifiers.json`, `src/report.rs` and
`tests/report.rs` retain their original SHA-256 values. The candidate is the
uncommitted lane diff on base `f92fe85970ad0898be4f5247cf580b1f5eaf4bda`;
these results describe the dirty candidate, rather than a committed change.
Evidence and the private lifecycle inventory are local and uncommitted under
`target/task-035/`. The ledger keeps 1 new retained test roots
(333 bytes) for supervisor review, with removal
when that review ends. The supervisor owns this cleanup decision.

Final handoff check: `target/host/debug/report --check-earlier-runs` exited 0;
all test Home processes have ended and the shared heavy-build lease is released.
The final branch/worktree inventory records five changed files, all inside
this lane. The current branch is zero commits ahead and zero behind the
cached `spike/spike/agent-host` ref; remote state was left unfetched under the
builder's network rule. The builder made zero Git-state changes. The current
worktree remains protected for supervisor review and publication.


## 032 — agent-host journal P7 gap and principal-bound deny journey

The default table now records the real agent-host journal as BLOCKED (UsersAI binding); the opt-in deny journey uses the same blocker and keeps its complete body, exact two-request assertion and label.

`tests/effects.rs::real_agent_host_journal_under_usersai_principal` reads the
real manifest through `build::repository()`, refuses a symlink, parses it with
`serde_json`, and requires each capability under `localhost://UsersAI/self/`.
The ignored body only reads the manifest. Runtime owns the verified launch
principal and `UsersAI/self` scope; agent-host owns the later journal move.
The existing report renderer supplies the P7 label, tested by
`tests/report.rs::p7_gap_row_is_blocked_with_label`. Both tests have rows in
the UsersAI table in `GAPS.md`; `RUNBOOK.md` names the active harness checks.

### Three-step F-agent-host-p7 run

All commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true`, the lane's `target/host` and `target/host-build`, and
the shared heavy-build lease. Each invocation had a 600-second bound.
The hand-run command for all three steps was:

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects real_agent_host_journal_under_usersai_principal -- --exact
```

The planted edit is exactly the F-agent-host-p7 edit in `falsifiers.json`:
remove only `#[ignore = "blocked: UsersAI binding"]` immediately before
`fn real_agent_host_journal_under_usersai_principal()`. The named function
makes the anchor unique. The original bytes were restored in a `finally`
block before the third step.

| Step | Exit | Seconds | Result |
| --- | --- | --- | --- |
| Baseline | 0 | 1.746 | ignored |
| Planted | 101 | 1.735 | FAILED, fixed P7 reason |
| Restored | 0 | 0.988 | ignored |

Exact libtest lines and failing assertion, in step order:

```text
test real_agent_host_journal_under_usersai_principal ... ignored, blocked: UsersAI binding
test real_agent_host_journal_under_usersai_principal ... FAILED
P7 gap: agent-host journal bound localhost://Users/self/.AppData/Agents/agent-host/* is not under UsersAI/self
test real_agent_host_journal_under_usersai_principal ... ignored, blocked: UsersAI binding
```

This catches premature activation of the placeholder. It supplies zero
principal-binding or live shell-denial acceptance. F-agent-host-grant is
retired under UsersAI binding until its real journey has a passing baseline.
A comparison against the base entry proved that its retired `file`, `old`
and `new` bytes match exactly; every other existing list entry is unchanged.

### Hand-run report-label falsifier

Command:

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report p7_gap_row_is_blocked_with_label -- --exact
```

The extra label falsifier is recorded here without a new list ID. Its exact
edit bytes, including the indentation, are:

```json
{
  "file": "src/report.rs",
  "old": "                text.push_str(\" | P7 gap: real agent-host journal under Users/self, not UsersAI/self; moves when the UsersAI binding lands\");",
  "new": "                text.push_str(\"\");"
}
```

| Step | Exit | Seconds | Result |
| --- | --- | --- | --- |
| Baseline | 0 | 0.828 | PASS |
| Planted | 101 | 1.557 | FAILED, exact table assertion |
| Restored | 0 | 1.408 | PASS |

```text
test p7_gap_row_is_blocked_with_label ... ok
test p7_gap_row_is_blocked_with_label ... FAILED
assertion `left == right` failed
test p7_gap_row_is_blocked_with_label ... ok
```

The restored source retains the exact label. The grader still owns blocker
validation and receipt grading; this task adds a label in that existing path.

### Principles check

Paths are relative to `lab/agent-conformance/`.

| Question | Answer | Evidence |
| --- | --- | --- |
| 1. New name or URL where a code/content hash belongs? | No | `tests/effects.rs:727` selects read-only source input; `src/identity.rs:91` retains the checked bundle CID for launches. |
| 2. Capsule, Home or UI gains ambient authority? | No | `tests/effects.rs:726` only reads the repository manifest; `tests/agent_host.rs:85` adds a blocker to the unchanged grant journey. |
| 3. A second path or rule copy for one operation? | No | `src/report.rs:218` adds the label to the existing table renderer; the existing grader validates both GAPS rows. |
| 4. Runtime core grows? | No | `tests/effects.rs:726` keeps the new check in this lab lane; Runtime, provider and capsule source bytes remain unchanged. |
| 5. New refusals fail closed with a clear reason? | Yes | `tests/effects.rs:728` refuses a non-regular manifest; `tests/effects.rs:742` refuses a capability outside UsersAI/self with the fixed P7 reason. |
| 6. Capsule logic stays inside and calls through granted Bus operations? | Yes | `probe/src/lib.rs:138` retains the grant request and `probe/src/lib.rs:146` retains the provider call; the real capsule and probe keep their base bytes. |
| 7. Named tests and caught falsifiers prove each new rule? | Yes | `tests/effects.rs:726` fails under F-agent-host-p7; `tests/report.rs:278` fails under the label mutation. All named tests failed while planted and returned to their required states after restore. |
| 8. Identity, admission and allowance remain separate decisions? | Yes | `src/report.rs:521` retains the separate identity, admission and session-grant statement; a manifest namespace check supplies zero execution or budget authority. |

The repository has no humanizer skill source. This record uses direct
statements of behavior and ownership. The supervisor owns review and publication.

### Required gates and real table runs

The restored candidate passed the lane formatting gate in 0.132 seconds
(exit 0) and `cargo test --locked --manifest-path
lab/agent-conformance/Cargo.toml` in 267.476 seconds (exit 0): 84 passed,
zero failed, 11 ignored with blockers. Both gates stayed within 600 seconds.
The first sandboxed locked run exited 101 in 3.087 seconds because
`earlier_run_check_refuses_live_owner` could not inspect its child process
group. The unchanged host-access run supplied the passing gate above.

The real `./run.sh` run exited 1 in 249.559 seconds. Its P7 row was:

```text
real_agent_host_journal_under_usersai_principal | BLOCKED (UsersAI binding) | P7 gap: real agent-host journal under Users/self, not UsersAI/self; moves when the UsersAI binding lands
```

That table's unrelated `cleanup_census_refuses_each_leftover` row read FAIL
at its final cleanup check (`tests/runtime.rs:394`):

```text
process leftover; processes:3 paths:["stderr-27", "stdout-25", "stdout-27"] API sockets:0 temp:0 paths:[]
```

The same test passed in the full locked gate. Its source and assertions retain
their base bytes. The default table's version receipt passed A14; the failed
run remains recorded as a failure, separate from the P7 BLOCKED evidence.

The real `./run.sh --agent-host` run exited 0 in 254.303 seconds: 102 PASS
test rows, 12 BLOCKED rows, zero FAIL and zero SKIPPED rows. Its version
receipt passed A14. Both requested rows came from that real table:

```text
real_agent_host_gets_no_ungranted_authority | BLOCKED (UsersAI binding) | real agent-host capsule, deny half; no model call (RT3)
real_agent_host_journal_under_usersai_principal | BLOCKED (UsersAI binding) | P7 gap: real agent-host journal under Users/self, not UsersAI/self; moves when the UsersAI binding lands
```

The unchanged cleanup test also passed in the opt-in run. A final isolated
recheck used:

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --exact
```

It exited 0 in 2.019 seconds:

```text
test cleanup_census_refuses_each_leftover ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.75s
```

This passing recheck supports a transient cleanup-census failure in the plain
table run; it preserves that earlier failure record. The code for that test
and the census is unchanged. Final lane formatting passed again in 0.179
seconds. `git diff --check`, product-data validation (42 capsules, two
profiles, 28 method contracts), all 99 product-data Node tests, Runtime and
chain-provider formatting, and `bash -n lab/agent-conformance/run.sh` passed.

The Mac had 45.27 GiB free before the full gate and table runs, above the
12 GiB build estimate plus 2 GiB reserve. The same shared heavy-build lease
covered each heavy command and is now released. The final report
`--check-earlier-runs` check exited 0 in 1.359 seconds; test Home processes
have ended. `Cargo.toml` and `Cargo.lock` retain their initial SHA-256 values.
Seventeen existing falsifier anchors in the changed files retain their base
match counts. The only new active list ID is F-agent-host-p7; its manual run
above supplies the mutation evidence while shared-runner routing stays with
its owner.

The candidate is the uncommitted eight-file lane diff. Evidence and the local
lifecycle inventory are private, uncommitted files in `target/task-032/`.
The inventory retains this task's test roots and table receipts for supervisor
review, with removal when that review ends; the supervisor owns that cleanup.
The current branch is zero commits ahead and 11 commits behind the cached
`spike/spike/agent-host` ref at handoff. The cached ref advanced during testing;
this worktree's HEAD remains the tested base `04f1e93b4789d3f86474abe77d89aeadf12e35a0`.
The builder made zero fetches or Git-state changes under the network rule.
The supervisor owns current-base integration, review and publication.

## 033 — One sibling-read rule for the barrier, cancel and kill checks

`sibling_read` in `tests/common/grants.rs` is the one sibling-read rule. For instance `index` it requires that instance's session, the other instance's file, action read, that instance's sibling reason, and a request id absent from the first barrier. `barrier_decision`'s stage-1 branch and `Overlap::ready_after_cancel` both call it. The overlap, cancel and kill refusal strings stay as they were. The stopped instance's further-request check stays in `ready_after_cancel` and compares that instance's session only. `overlap_second_barrier_waits_for_both_requests` starts 3-second `sleep` clients and still collects them with the existing 5-second bound. `RUNBOOK.md` says the overlap, cancel and kill rows share this rule. `src/report.rs` is unchanged.

### Hand-run falsifiers

Both entries use `"command": "lab"`. Each step used `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects TEST -- --exact --test-threads=2` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and the lane `target/host` directories. Source bytes were restored after each planted step. Every named test passed before the edit, failed while planted, and passed after restoration.

F-overlap-sibling-new replaces the helper's request-id clause with `true`:

```text
old: !first\n            .iter()\n            .any(|first| first["request_id"] == request["request_id"])
new: true
```

`grants::tests::overlap_sibling_read_must_be_new_in_its_session`:

```text
baseline: exit 0, 0.115s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 1.371s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... FAILED
assertion `left == right` failed: sibling rule must check request_id
 right: Err("overlap: sibling read must be new in its original session")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 1.158s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

`grants::tests::cancel_refuses_retries_and_unexpected_requests` (its `request_id` case is the first case that becomes `Ok(true)`; resource and session still refuse):

```text
baseline: exit 0, 0.068s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 0.085s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... FAILED
assertion `left == right` failed
  left: Ok(true)
 right: Err("cancel: unexpected request after cancellation")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 0.081s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

`grants::tests::kill_sibling_read_must_be_new_in_its_session`:

```text
baseline: exit 0, 0.068s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 0.067s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... FAILED
assertion `left == right` failed: kill sibling rule must check request_id
  left: Ok(true)
 right: Err("no-retry check: unexpected request after worker kill")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 0.066s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

F-sibling-one-rule replaces only the helper's resource comparison with `true`:

```text
old: request["resource"] == first[1 - index]["resource"]
new: true
```

`grants::tests::overlap_sibling_read_must_be_new_in_its_session`:

```text
baseline: exit 0, 0.066s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 0.981s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... FAILED
assertion `left == right` failed: sibling rule must check resource
 right: Err("overlap: sibling read must be new in its original session")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 1.146s
test grants::tests::overlap_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

`grants::tests::cancel_refuses_retries_and_unexpected_requests` (the loop's first case is `("resource", "fixture-b")`, so this failure is that case):

```text
baseline: exit 0, 0.065s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 0.149s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... FAILED
assertion `left == right` failed
  left: Ok(true)
 right: Err("cancel: unexpected request after cancellation")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 0.080s
test grants::tests::cancel_refuses_retries_and_unexpected_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

`grants::tests::kill_sibling_read_must_be_new_in_its_session`:

```text
baseline: exit 0, 0.065s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
planted: exit 101, 0.206s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... FAILED
assertion `left == right` failed: kill sibling rule must check resource
  left: Ok(true)
 right: Err("no-retry check: unexpected request after worker kill")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
restored: exit 0, 0.068s
test grants::tests::kill_sibling_read_must_be_new_in_its_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 0.00s
```

`F-cancel-retry` and `F-kill-monitor` still anchor on the unchanged `ready_after_cancel` signature, once each. Their anchors did not move, so they were left in place and were not re-run. `F-census-a` and `F-ac2c` already missed their anchors on this base.

### Wiring window and live journeys

`grants::tests::overlap_second_barrier_waits_for_both_requests` with 3-second clients and the existing 5-second `collect` bound:

```text
exit 0, wall 4.788s
test grants::tests::overlap_second_barrier_waits_for_both_requests ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 3.06s
```

The same command with `--show-output` ran the three journeys once. All passed:

```text
test two_instances_overlap_with_separate_grants ... ok
instance overlap: instance-1 instance-2 barriers:2 first:0.039284s second:0.229690s overlap:0.268180s elapsed:5.362805s; process-isolation lab half of A3, A6 and A9
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 12.75s

test cancelled_instance_settles_with_reason_sibling_completes ... ok
cancel settlement: instance-1 exit:Some(1) signal:None elapsed:0.157588s kill_at:0.000000s; instance-2 exit:Some(1) signal:None elapsed:0.389891s kill_at:0.000000s; first:0.026568s overlap:0.025309s since_decision:5.347494s; reason:fixture cancel: instance-1 cancelled mid-run; cancel at the pending-request point, lab half of A10 (A12 census)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 12.69s

test killed_worker_settlement_recorded_without_retry ... ok
kill settlement: instance-1 exit:None signal:Some(9) elapsed:0.058766s kill_at:0.034001s; instance-2 exit:Some(1) signal:None elapsed:0.333574s kill_at:0.000000s; first:0.033501s overlap:0.032483s since_decision:5.851066s; reason:fixture settlement: worker killed; orphan_before:1 orphan_after:0; settled by the fixture; quiet:2.012286s; kill-worker settlement, lab half of A11 (A12 census)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 12.12s
```

Wall times for those three commands were 12.829s, 12.805s and 12.189s.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a code or content hash belongs? | No | `tests/common/grants.rs:220` compares a pending request's session, resource, action, reason and request id. |
| 2. Capsule, Home or UI gains ungranted access? | No | `probe/src/lib.rs:138` still requests the read, and `:146` invokes the provider with that grant. The probe is unchanged. |
| 3. A second path or a second copy of one rule? | No | `tests/common/grants.rs:222` holds the session comparison, `:223` the resource comparison, `:227` the request-id comparison, `:217` the read comparison, and `:213` the sibling-reason comparison. `:276` and `:379` call `sibling_read`. |
| 4. Runtime core grows? | No | The edit is the lab harness in `tests/common/grants.rs:220`. Runtime, provider and probe sources are unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/common/grants.rs:277` keeps `overlap: sibling read must be new in its original session`. `:380` keeps the cancel and kill unexpected-request refusals. `:371` keeps the stopped instance's further-request refusal. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `probe/src/lib.rs:138` requests the capability and `:146` passes the grant to the provider. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/common/grants.rs:1800` is the new kill test. `falsifiers.json:1348` and `:1366` are the two planted bugs. All three named tests failed for each bug and passed after restoration. |
| 8. Identity, admission and allowance stay separate? | Yes | `tests/common/grants.rs:220` checks request shape. `:270` still matches the fixture grant for an own read. Bundle identity stays on the existing receipt path. |

### Gates

Both commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and the lane `target/host` and `target/host-build` directories, under the shared heavy-build lease. The volume had about 45 GiB free before the runs.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: PASS, exit 0, 0.122 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: PASS, exit 0, 255.480 seconds, inside the 600-second bound. 85 passed, 0 failed, 11 ignored. The effects target passed 35 tests, with 10 ignored, in 202.20 seconds.

`Cargo.toml` and `Cargo.lock` are unchanged. The builder made no Git-state changes.
