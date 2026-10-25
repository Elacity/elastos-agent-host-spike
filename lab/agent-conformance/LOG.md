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
