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

## 036 — CID launch blocker names what is left after the directory CID

036 records that the lab CID is now a CIDv1 dag-pb UnixFS directory root (cc-capsule-identity 018, PR #226), and names the three conditions still required before `capsule_named_by_hash` can run. AC-025-CID stays the blocker. This task adds no rule, no test, and no `falsifiers.json` id.

`GAPS.md` replaces the stale identity paragraph, and the row's change cell and the flip paragraph name, in order: a measured Kubo v0.40.1 match for the staged probe bundle, the offline content fixture, and `--cid` reaching the directory launch's activation. The ID cell stays `AC-025-CID`. `RUNBOOK.md` states the same three conditions and the fenced-row parser limit. `capsule_named_by_hash` keeps `#[ignore = "blocked: AC-025-CID"]` and its panic names the same three conditions.

### Gate and hand-run of the row

Commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` under the shared heavy-build lease. `./run.sh` sets the lane `target/host` and `target/host-build` directories. Free space was about 43 GiB.

Baseline `./run.sh`: exit 0, 257.881 seconds. No FAIL row. Table line:

```text
capsule_named_by_hash | BLOCKED (AC-025-CID)
```

The ID cell was then changed to `AC-025-CIDX` and restored afterward. `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report`: exit 0, 2.137 seconds. `test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.62s`. Those tests grade synthetic rows. The live grader is `./run.sh`.

Planted `./run.sh`: exit 1, 248.618 seconds. FAIL line:

```text
capsule_named_by_hash | FAIL | GAPS.md: capsule_named_by_hash: missing blocker IDs: [AC-025-CID]; extra blocker IDs: [AC-025-CIDX]
```

`versions_receipt (A14) | FAIL` followed that suite failure. The receipt failure was the same GAPS sentence. The ID cell was reverted to `AC-025-CID`.

Restored `./run.sh`: exit 0, 252.652 seconds. No FAIL row. Table line:

```text
capsule_named_by_hash | BLOCKED (AC-025-CID)
```

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, 0.11 seconds. `Cargo.toml` and `Cargo.lock` are unchanged. The builder made no Git-state changes.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `GAPS.md:144` names the lab CID as the directory root. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/runtime.rs:142` stays ignored. The probe is unchanged. |
| 3. A second path or a second copy of one rule? | No | `src/report.rs:37` remains the one blocked-row check. |
| 4. Runtime core grows? | No | The edit is `GAPS.md`, `RUNBOOK.md` and the ignored test's panic text. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/runtime.rs:147` still stops the journey and names what is left. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The probe source is unchanged. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | No new rule. The planted ID cell above is the existing grader, and it is not a list id. |
| 8. Identity, admission and allowance stay separate? | Yes | `GAPS.md:171-173` keeps those decisions separate. A valid CID gives no grant. |

## 037 — Kill row reasons and the denial count use one settlement rule

037: `check_kill`'s last refusal names overlap and the quiet window; `instance_read_result` requires two denials and no longer builds that count from the settlement; `poll` uses one orphan filter and returns the changed-orphan reason.

`Controller::check_kill` still calls `Settlement::check` for the orphan count. Its last branch only checks overlap and the quiet window, and its refusal is `kill: overlap and quiet window are required`. No other refusal string changed. `kill_requires_measured_fixture_settlement` keeps its assertions.

`instance_read_result` no longer takes a settlement. Every instance outcome requires `denied == 2`. Cancel and kill still require one grant. The orphan count stays in `Settlement::check` (`tests/common/grants.rs:172`). A settlement of 0 or 2 orphans denies 1 or 3 times, so this comparison fails on its own. `grep -n before tests/effects.rs` leaves `orphan.before` only at `tests/effects.rs:513`, where the absent-policy journey compares its denial total with the measured pending length. That line builds no kill count.

`active_requests` is the one filter. `Controller::poll` calls it once (`tests/common/grants.rs:713`). The exact original orphan is dropped. A new request id stays and reaches the retry rule. The same id with a changed field returns `orphan request changed while pending`. `poll_gives_changed_orphan_its_own_reason` calls `Controller::poll` for all three.

### Hand-run falsifiers

There is no new list id. The runner's `lab` command runs `lab/wasm-capsule` (BACKLOG item 7). Each mutation was restored before the next one. Each old-text anchor occurred once before the plant and once after restore.

Commands were `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects TEST -- --exact --nocapture` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`, and the shared heavy-build lease. In the old/new cells, `\n` is one newline.

| ID | File | Exact old text | Exact new text | Named test | Libtest lines and results | Failing assertion |
| --- | --- | --- | --- | --- | --- | --- |
| F-poll-orphan-wiring | `tests/common/grants.rs` | the call line below | the swallowed call line below | `grants::tests::poll_gives_changed_orphan_its_own_reason` | baseline: `test grants::tests::poll_gives_changed_orphan_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.02s` (exit 0, 0.923 s)<br>planted: `test grants::tests::poll_gives_changed_orphan_its_own_reason ... FAILED / test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.02s` (exit 101, 1.072 s)<br>restored: `test grants::tests::poll_gives_changed_orphan_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.02s` (exit 0, 0.885 s) | `assertion left == right failed: a changed orphan keeps its own reason on the live poll path; left: Err("no-retry check: killed worker made a further request"); right: Err("orphan request changed while pending")` |
| F-orphan-owner | `tests/common/grants.rs` | `        if self.before == 0 {\n            return Err("orphan already settled when measured; re-measure AC-027-ORPHAN and name the Runtime source line");\n        }\n        if self.before != 1 {` | `        if self.before > 1 {` | `grants::tests::kill_requires_measured_fixture_settlement` | baseline: `test grants::tests::kill_requires_measured_fixture_settlement ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 0, 0.825 s)<br>planted: `test grants::tests::kill_requires_measured_fixture_settlement ... FAILED / test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 101, 0.989 s)<br>restored: `test grants::tests::kill_requires_measured_fixture_settlement ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 0, 0.847 s) | `assertion left == right failed: kill requires exactly one measured orphan and zero after settlement; left: Ok(()); right: Err("orphan already settled when measured; re-measure AC-027-ORPHAN and name the Runtime source line")` |
| F-orphan-match | `tests/common/grants.rs` | `    let same_id = field(request, "request_id")? == field(original, "request_id")?;\n    if same_id && request != original {\n        return Err("orphan request changed while pending");\n    }\n    Ok(same_id && field(request, "session_id")? == field(original, "session_id")?)` | `    Ok(field(request, "request_id")? == field(original, "request_id")?)` | `grants::tests::changed_orphan_has_its_own_reason` | baseline: `test grants::tests::changed_orphan_has_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 0, 1.624 s)<br>planted: `test grants::tests::changed_orphan_has_its_own_reason ... FAILED / test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 101, 1.091 s)<br>restored: `test grants::tests::changed_orphan_has_its_own_reason ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s` (exit 0, 0.853 s) | `assertion left == right failed: a changed orphan needs its own reason; left: Ok(true); right: Err("orphan request changed while pending")` |

F-poll-orphan-wiring replaces this call in `Controller::poll`. The closure characters are the exact bytes:

```text
        let pending = active_requests(pending, self.overlap.as_ref())?;
        let pending = active_requests(pending, self.overlap.as_ref()).unwrap_or_else(|_| pending.clone());
```

The first line is the old text, including its newline. The second line is the planted text, including its newline. F-poll-orphan-wiring swallows the filter error at the `poll` call site. The planted test then reports the retry reason. F-orphan-owner and F-orphan-match use the same bytes as 035. Their anchors still match once. `falsifiers.json` is unchanged. Item 2 adds no rule, so it has no new falsifier.

### Kill journey

`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects killed_worker_settlement_recorded_without_retry -- --exact --nocapture` exited 0 in 14.223 s. Libtest: `test killed_worker_settlement_recorded_without_retry ... ok` and `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 13.14s`.

```text
kill settlement: instance-1 exit:None signal:Some(9) elapsed:0.057638s kill_at:0.030282s; instance-2 exit:Some(1) signal:None elapsed:0.329145s kill_at:0.000000s; first:0.029879s overlap:0.028939s since_decision:5.922889s; reason:fixture settlement: worker killed; orphan_before:1 orphan_after:0; settled by the fixture; quiet:2.013832s; kill-worker settlement, lab half of A11 (A12 census)
```

### Gates

Commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`, and the shared heavy-build lease. The volume had 41 GiB free. Each command stayed inside 600 seconds.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, 0.132 s.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, 218.348 s. `ungranted_memory_write_is_refused` failed in the cleanup census: `process leftover; processes:1 paths:["home/Library/Application Support/elastos/host-process.lock"]`.
- Same command, rerun: exit 101, 221.562 s. `cancelled_instance_settles_with_reason_sibling_completes` failed with the same census leftover. The code was unchanged.
- Same command, one further run: exit 0, 221.330 s. 86 passed, 0 failed, 11 ignored. The effects target passed 36 tests, with 10 ignored, in 173.84 s.

`Cargo.toml`, `Cargo.lock` and `falsifiers.json` are unchanged. The builder made no Git-state changes.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `src/identity.rs:91` still records the bundle lab CID. `tests/common/grants.rs:209` filters pending requests. |
| 2. Capsule, Home or UI gains ungranted access? | No | `probe/src/lib.rs:138` requests the grant before the provider call at `:146`. |
| 3. A second path or a second copy of one rule? | No | `tests/common/grants.rs:172` owns the orphan count. `:209` is the one poll filter, called at `:713`. `tests/effects.rs:626` compares the denial total with 2. |
| 4. Runtime core grows? | No | The edit is `tests/common/grants.rs` and `tests/effects.rs`. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/common/grants.rs:603` names overlap and the quiet window. `:1859` requires the changed-orphan reason from `poll`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `probe/src/lib.rs:138` requests the capability and `:146` passes the grant to the provider. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/common/grants.rs:1840` fails when `poll` swallows the filter error. F-orphan-owner and F-orphan-match still fail when planted. |
| 8. Identity, admission and allowance stay separate? | Yes | `src/report.rs:521` keeps the bundle CID, admission and the session grant separate. A settlement count grants nothing. |

## 041 — Land reviewed A5 session rows

041 lands the reviewed 038 tree for rows (a), (b) and (d) on the current base. `git merge-file` used base `6f0eb5a5cbb6cb14071effecd4b317351731bd87` (`git merge-base HEAD 0da4b9b3e3c52cb04b555e37f657a0e590ac5a14`) and other `0da4b9b3e3c52cb04b555e37f657a0e590ac5a14`. All seven files merged with exit 0 and no conflict markers: `GAPS.md`, `RUNBOOK.md`, `run.sh`, `src/report.rs`, `tests/common/grants.rs`, `tests/effects.rs`, `tests/report.rs`. `LOG.md` was not merged. `Cargo.toml`, `Cargo.lock` and `falsifiers.json` are unchanged. There is no new list id.

The merge keeps, once each, `fn active_requests` (`tests/common/grants.rs:209`), `fn barrier_decision` (`:247`), the refusal `kill: overlap and quiet window are required` (`:647`), and the `capsule_named_by_hash` ID cell `AC-025-CID` (`GAPS.md:84`). `src/report.rs:234` still says `process-isolation lab half of A3, A6 and A9`. `client_session` (`tests/common/grants.rs:855`) and `grant_names_verified_agent` (`:1705`) are present. `run.sh:42` prints lines that start with `session grant`.

Rows (a) and (b) are `grant_refused_from_another_session` and `grant_refused_from_a_new_session`. Both call `exercise_session_binding`. Row (d), `grant_record_names_agent_identity`, stays `#[ignore = "blocked: AC-038-GRANT-PRINCIPAL"]`. A permitted Public read remains the positive control and earns no A5 credit.

### Hand-run falsifiers

Commands used `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`, and the shared heavy-build lease. The lease was free. Each old anchor occurred once. Each plant was restored before the next step. The volume had about 40 GiB free.

#### F-a5-other-session

The other-session arm presents the owner. The replaced line is `SessionBinding::OtherSession => other.as_ref().unwrap(),`, and the planted line is `SessionBinding::OtherSession => &owner,`.

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects -- grant_refused_from_another_session --exact --nocapture --test-threads=2
```

Unmutated: exit 0, 14.260 seconds.

```text
test grant_refused_from_another_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 61 filtered out; finished in 12.15s
```

Planted: exit 101, 14.118 seconds.

```text
thread 'grant_refused_from_another_session' (61106448) panicked at tests/effects.rs:932:10:
another session cannot present the grant: "presenting session was not refused"
test grant_refused_from_another_session ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 61 filtered out; finished in 11.49s
```

Restored: exit 0, 13.883 seconds.

```text
test grant_refused_from_another_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 61 filtered out; finished in 11.91s
```

#### F-a5-new-session

The new-session arm presents the owner. The replaced line is `SessionBinding::NewSession => renewed.as_ref().unwrap(),`, and the planted line is `SessionBinding::NewSession => &owner,`.

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects -- grant_refused_from_a_new_session --exact --nocapture --test-threads=2
```

Unmutated: exit 0, 11.321 seconds.

```text
test grant_refused_from_a_new_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 61 filtered out; finished in 11.18s
```

Planted: exit 101, 13.323 seconds.

```text
thread 'grant_refused_from_a_new_session' (61117523) panicked at tests/effects.rs:939:10:
a new session cannot present the grant: "presenting session was not refused"
test grant_refused_from_a_new_session ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 61 filtered out; finished in 11.19s
```

Restored: exit 0, 10.870 seconds.

```text
test grant_refused_from_a_new_session ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 61 filtered out; finished in 9.43s
```

#### F-a5-gap-row

The new `GAPS.md` ID cell changes from `AC-038-GRANT-PRINCIPAL` to `AC-038-GRANT-PRINCIPALX` on the `grant_record_names_agent_identity` row only. `./run.sh` from `lab/agent-conformance`:

| Step | Exit | Seconds | Row |
| --- | --- | --- | --- |
| Unmutated | 0 | 297.287 | `grant_record_names_agent_identity \| BLOCKED (AC-038-GRANT-PRINCIPAL)` |
| Planted | 1 | 282.639 | `grant_record_names_agent_identity \| FAIL \| GAPS.md: grant_record_names_agent_identity: missing blocker IDs: [AC-038-GRANT-PRINCIPAL]; extra blocker IDs: [AC-038-GRANT-PRINCIPALX]` |
| Restored | 0 | 286.630 | `grant_record_names_agent_identity \| BLOCKED (AC-038-GRANT-PRINCIPAL)` |

The planted run also printed `versions receipt failure:` with that same missing/extra ID text. On every run, rows (a) and (b) stayed PASS with the session-binding label. The ID cell is restored. The restored table has no FAIL row.

### Acceptance run

The restored `./run.sh` above is the acceptance run on this head: exit 0, 286.630 seconds. No FAIL row.

```text
grant_refused_from_another_session | PASS | session binding of a Runtime grant on the run client's route, lab client sessions (M1 A5 half); a Public read earns no A5 credit
grant_refused_from_a_new_session | PASS | session binding of a Runtime grant on the run client's route, lab client sessions (M1 A5 half); a Public read earns no A5 credit
grant_record_names_agent_identity | BLOCKED (AC-038-GRANT-PRINCIPAL)
```

### Gates

The same environment and lease as the falsifiers. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, 0.126 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, 359.885 seconds. 104 passed, 0 failed, 12 ignored. The effects target passed 51 tests, with 11 ignored, in 276.09 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `tests/effects.rs:820` records the Runtime SHA-256 for the session journey. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/common/grants.rs:994` accepts a cross-session presentation only as the Runtime 403. |
| 3. A second path or a second copy of one rule? | No | `tests/common/grants.rs:998` is the one provider read for the granted read and the presentation. |
| 4. Runtime core grows? | No | `tests/common/grants.rs:1705` keeps the principal comparison in the lane harness. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/common/grants.rs:1714` denies when verified caller evidence is unavailable. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/common/grants.rs:1008` sends the provider read with the granted token. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:930` fails under F-a5-other-session. The planted gap cell fails in the report. |
| 8. Identity, admission and allowance stay separate? | Yes | `tests/effects.rs:856` keeps the Public read off A5 credit. `:954` passes no verified caller. |

## 039 — Owned storage root row, and A3 relabelled as process isolation

039 records `instance_writes_only_under_own_storage_root` as `BLOCKED (AC-039-OWNED-ROOT)` and relabels the two-client rows as process isolation, not A3. `Cargo.toml`, `Cargo.lock` and `falsifiers.json` are unchanged. There is no new list id.

### Ignored journey

`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects -- instance_writes_only_under_own_storage_root --exact --nocapture --ignored --test-threads=2` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. Exit 101, real 10.96 seconds. Each session wrote its own file. The sibling request stayed pending, the existing deny route settled it, and the test then failed.

```text
owned root: write localhost://Public/agent-conformance-grants/instance-a/own.txt status:ok bytes:10
owned root: write localhost://Public/agent-conformance-grants/instance-b/own.txt status:ok bytes:10
owned root: sibling request localhost://Public/agent-conformance-grants/instance-a/sibling.txt status:pending
fixture controller: denied
thread 'instance_writes_only_under_own_storage_root' (62680033) panicked at tests/effects.rs:1056:28:
Runtime refuses a sibling write under the other owned root: "Runtime left the sibling write pending for the shell"
test instance_writes_only_under_own_storage_root ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 68 filtered out; finished in 10.86s
```

The cleanup line was `pending:0 grants:BLOCKED(AC-021-GRANTS)`.

### F-a3-label

`src/report.rs` `INSTANCE_GRANTS_SCOPE` was set back to `process-isolation lab half of A3, A6 and A9`. No other file changed.

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test report -- --test-threads=2
```

Exit 101, real 2.65 seconds.

```text
thread 'instance_receipt_requires_both_launches_and_scope' (62691114) panicked at tests/report.rs:1029:9:
assertion failed: complete.table.contains(&format!("{name} | PASS | {scope}"))
test result: FAILED. 22 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.35s
```

The constant was restored before the next step. The restored report target later passed 23 tests.

### F-a5-root-gap-row

The new row's ID cell was `AC-039-OWNED-ROOTX`. `./run.sh` from `lab/agent-conformance`. The first planted run also hit the known `fixture_operator_sockets_are_loopback_only` census flake. Nothing was changed for that flake. The planted command was run once more. `owned_root_row_is_blocked_in_gaps` reads `GAPS.md`, so that test fails while the ID cell is planted.

| Step | Exit | Seconds | Row |
| --- | --- | --- | --- |
| Planted, with the socket flake | 1 | 289.66 | `instance_writes_only_under_own_storage_root \| FAIL \| GAPS.md: instance_writes_only_under_own_storage_root: missing blocker IDs: [AC-039-OWNED-ROOT]; extra blocker IDs: [AC-039-OWNED-ROOTX]` |
| Planted, rerun | 1 | 269.12 | same FAIL line; `fixture_operator_sockets_are_loopback_only \| PASS` |
| Restored | 0 | 248.45 | `instance_writes_only_under_own_storage_root \| BLOCKED (AC-039-OWNED-ROOT)` |

The flake text was `process leftover; processes:1 paths:["home/Library/Application Support/elastos/host-process.lock"]`. On both planted runs, `grant_refused_from_another_session` and `grant_refused_from_a_new_session` stayed PASS with the session-binding label, and `grant_record_names_agent_identity` stayed `BLOCKED (AC-038-GRANT-PRINCIPAL)`. The ID cell is restored.

### Acceptance run

The restored `./run.sh` above is the acceptance run: exit 0, real 248.45 seconds. No FAIL row. `versions_receipt (A14) | PASS`.

```text
grant_refused_from_another_session | PASS | session binding of a Runtime grant on the run client's route, lab client sessions (M1 A5 half); a Public read earns no A5 credit
grant_refused_from_a_new_session | PASS | session binding of a Runtime grant on the run client's route, lab client sessions (M1 A5 half); a Public read earns no A5 credit
grant_record_names_agent_identity | BLOCKED (AC-038-GRANT-PRINCIPAL)
instance_writes_only_under_own_storage_root | BLOCKED (AC-039-OWNED-ROOT)
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 249.44 seconds. The effects target passed 57 tests, with 12 ignored, in 196.85 seconds. The report target passed 23 tests. `fixture_operator_sockets_are_loopback_only` passed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `GAPS.md:966` names the Runtime change by its existing issue. The receipt hash fields are unchanged. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/common/grants.rs:1011` sends the owned-file write with the session grant token. |
| 3. A second path or a second copy of one rule? | No | `tests/common/grants.rs:926` is the one request-and-grant path for read and write. |
| 4. Runtime core grows? | No | `tests/effects.rs:1054` keeps the blocked journey in the lane harness. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/common/grants.rs:1840` accepts only `denied` or `auto_denied` with a reason. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/common/grants.rs:1010` writes through the existing provider route. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:1056` fails while the sibling request is pending. F-a5-root-gap-row and F-a3-label fail when planted. |
| 8. Identity, admission and allowance stay separate? | Yes | `GAPS.md:966` keeps the owned root bound to identity and session. A granted write does not close the row. |

## 040 — Launch does not compare bytes with the signed record

040: `launch_refuses_bytes_unlike_signed_record` is BLOCKED (AC-040-RECORD-LAUNCH). `elastos run` finds an installed release capsule by name and does not compare the launched bytes with that capsule's signed record.

`verify_capsule_signature` (`elastos/crates/elastos-server/src/runtime.rs:351-408`) is the launch check, called from `run_local_with_principal` (`runtime.rs:282`) on the component path (`run_cmd.rs:264-267`). For an installed signed release, an unsigned capsule calls `verify_installed_release_capsule` (`setup.rs:1596-1625`). That function looks up `manifest.name` (`setup.rs:1606`), checks the install path (`setup.rs:1613-1617`), and checks sidecar install state (`setup.rs:1771-1785`). It does not hash the launched directory. `CapsuleRecords::admit` (`capsule_record.rs:84-98`) compares `record.sha256` and `record.cid` with the release row at setup and update (`setup.rs:739`, `update.rs:1192`), not from `run_local`. A signed manifest hashes the entrypoint file only (`runtime.rs:389-404`). Records stay optional (`capsule_record.rs:18`). The lane does not copy the release signing format, so it does not build that Home. The live pair stays out. Anders owns the record-to-launch repair (https://github.com/Elacity/elastos-runtime/issues/274).

`GAPS.md` "Launch by bundle CID (025)" cites this result as BLOCKED (AC-040-RECORD-LAUNCH). The `capsule_named_by_hash` ID cell stays `AC-025-CID`. `RUNBOOK.md` has one line for the new row. There is no new `falsifiers.json` id. `Cargo.toml` and `Cargo.lock` are unchanged.

### Measured launch

A refusal before any record check; not B1. For one command only, `fixtures/operator-config.toml` was `dev_mode = false` with the same loopback Carrier bind. The file was restored afterward. `git diff` shows no fixture change. A temporary test, removed before the gates, started the operator with `Operator::start`, staged `identity::MANIFEST` through `identity::stage_probe`, and launched `elastos run` on that directory. The copied config contained `dev_mode = false`.

```bash
cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test runtime measure_unsigned_refusal_before_record_check -- --exact --nocapture --test-threads=1
```

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. Exit 0 for the test harness, real 23.16 seconds. Libtest: `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 10.08s`. The Runtime exit status was 1. Stderr:

```text
INFO elastos_server::runtime: Capsule signatures enforced with 0 trusted key(s)
INFO elastos_server::runtime: Loading capsule 'agent-conformance-probe' (Wasm)
Error: Component capsule failed: Invalid manifest: Capsule 'agent-conformance-probe' is unsigned; only a source or development Home with dev_mode = true runs unsigned capsules
```

That info line is the refused-unsigned arm (`runtime.rs:220-223`), not the installed-release arm (`runtime.rs:215-218`). The error is `runtime.rs:374-377`, before `verify_installed_release_capsule` (`runtime.rs:365-372`). Stderr had no `differs from the signed release` and no `Component capsule 'agent-conformance-probe' exited`. The cleanup line was `cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)`.

### Grader

The new row's ID cell was `AC-040-RECORD-LAUNCHX`, then restored to `AC-040-RECORD-LAUNCH`. `./run.sh` from the repository root. No census flake, so no rerun.

| Step | Exit | Seconds | Row |
| --- | --- | --- | --- |
| Planted | 1 | 322.70 | `launch_refuses_bytes_unlike_signed_record \| FAIL \| GAPS.md: launch_refuses_bytes_unlike_signed_record: missing blocker IDs: [AC-040-RECORD-LAUNCH]; extra blocker IDs: [AC-040-RECORD-LAUNCHX]` |
| Restored | 0 | 271.51 | `launch_refuses_bytes_unlike_signed_record \| BLOCKED (AC-040-RECORD-LAUNCH)` |

On the planted run, `versions_receipt (A14) | FAIL` used the same GAPS sentence. On the restored run it was `versions_receipt (A14) | PASS`. `capsule_named_by_hash` stayed `BLOCKED (AC-025-CID)`. The restored run is the acceptance run: exit 0, real 271.51 seconds, no FAIL row.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun. The volume had about 32 GiB free.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.12 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 278.68 seconds. The target summaries sum to 111 passed, 0 failed, 14 ignored. The effects target passed 57 tests, with 12 ignored, in 220.24 seconds. The runtime target passed 10 tests, with 2 ignored, in 14.07 seconds. The report target passed 23 tests.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `tests/runtime.rs:154` names the missing comparison with the record `sha256` or `cid`. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/runtime.rs:151` leaves the journey ignored. The probe source is unchanged. |
| 3. A second path or a second copy of one rule? | No | `GAPS.md:1016` keeps the release signing format out of the lane. |
| 4. Runtime core grows? | No | The edit is `GAPS.md`, `RUNBOOK.md` and `tests/runtime.rs:151`. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/runtime.rs:155` stops the journey and names the missing byte comparison. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The probe source is unchanged. `GAPS.md:1024` says a valid record gives no grant. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/runtime.rs:151` is the ignored row. The planted ID cell above fails in `./run.sh`. There is no new list id. |
| 8. Identity, admission and allowance stay separate? | Yes | `GAPS.md:179` keeps record-to-launch apart from the CID row. `GAPS.md:1023` says an unsigned refusal is not this row. |

## 044 — RA-1 stand-in lists every live grant

044: `StandIn::get_capability_list` is the lab stand-in for `GET /api/capability/list` on both route forms. A shell sees every live grant and `scope` `all_sessions_live`. A client sees only its own grants. A client that asks for the global view is refused. Exhausted, revoked and expired grants stay out. `run_leaves_no_live_grant` stays blocked on the real Runtime. There is no new `falsifiers.json` id. `Cargo.toml` and `Cargo.lock` are unchanged.

The ask at `513988ebd:lab/runtime-asks/01-live-grant-view.md` cites `tests/common/grants.rs:788` and `:1220`. Those lines moved. The text followed is `tests/common/grants.rs:856` `let grants = self.call("GET", "/api/capability/list", &Value::Null)?;` and `live_grant_state` at `tests/common/grants.rs:1628-1641`, whose marker check is `if response["scope"] != "all_sessions_live"`. `parse_live_grants` at `35697329b:lab/resident-instances/src/http.rs:338` requires `scope` `all_sessions_live` and, on each entry, `request_id`, `session_id`, `resource` and `action`.

### Hand-run falsifiers

No list id. Each plant was restored before the next. Lib tests are `standin_runtime::tests::NAME`; a bare name with `--exact` runs nothing. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and lane `target/host` plus `target/host-build`. After the last restore, the stand-in file matched its pre-plant bytes (`sha256 84750ac5b78f6b94359a475fb5fc7c6825bb5788010c775fa7e88eec89544be6`). `git diff -- lab/agent-conformance/standin-runtime/mod.rs` prints nothing because the new file is untracked, and the plant expressions are absent from that file.

F-standin-grant-stub. Named test `standin_shell_sees_every_live_grant`. Planted exit 101 in 7.659 s. Restored exit 0 in 1.028 s. A second plant of the same bytes, also restored, panicked at the same assertion. Assertion: `src/../standin-runtime/mod.rs:259:9` `assertion left == right failed: the stand-in lists every live grant` left `{}` right `{"req-a", "req-b", "req-z"}`.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        if let Some(scope) = scope {
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "scope": LIVE_SCOPE, "capabilities": [] }));
        if let Some(scope) = scope {
```

F-standin-empty-marker. Named test `standin_empty_shell_view_has_the_scope_marker`. Planted exit 101 in 1.344 s. Restored exit 0 in 0.652 s. Assertion: `src/../standin-runtime/mod.rs:328:9` `the stand-in empty shell view has the scope marker` left `{"capabilities"}` right `{"capabilities", "scope"}`.

Old:

```text
fn body(shell: bool, capabilities: Vec<Value>) -> Value {
    if shell {
```

New:

```text
fn body(shell: bool, capabilities: Vec<Value>) -> Value {
    if shell && capabilities.is_empty() {
        return json!({ "capabilities": capabilities });
    }
    if shell {
```

F-standin-own-session. Named test `standin_client_sees_only_its_own_grant`. Planted exit 101 in 0.886 s. Restored exit 0 in 1.057 s. Assertion: `src/../standin-runtime/mod.rs:382:9` `the stand-in lists the caller's live grants and leaves the sibling out` left `{"req-a", "req-b", "req-s"}` right `{"req-a", "req-b"}`.

Old:

```text
        Caller::Client { session_id } => grant.session_id == session_id,
```

New:

```text
        Caller::Client { .. } => true,
```

F-standin-shell-only. Named test `standin_client_global_view_is_refused`. Planted exit 101 in 0.877 s. Restored exit 0 in 0.563 s. Assertion: `src/../standin-runtime/mod.rs:461:9` `the stand-in refuses a client global view: Ok(... "scope": String("all_sessions_live"))`.

Old:

```text
            if let Caller::Client { .. } = caller {
                return Err((403, "This endpoint requires shell privileges".to_owned()));
            }
```

New:

```text
            if let Caller::Client { .. } = caller {
                return Ok(self.render(Caller::Shell));
            }
```

F-standin-unknown-scope. Named test `standin_unknown_scope_is_refused`. Planted exit 101 in 0.906 s. Restored exit 0 in 0.592 s. Assertion: `src/../standin-runtime/mod.rs:483:17` `the stand-in refuses unknown scope "session": Ok(Object {"capabilities": Array [], "scope": String("all_sessions_live")})`.

Old:

```text
            if scope != LIVE_SCOPE {
                return Err((400, format!("unknown capability list scope: {scope}")));
            }
```

New:

```text
            if scope != LIVE_SCOPE {
                return Ok(self.render(Caller::Shell));
            }
```

F-standin-live-filter. Named test `standin_dead_grants_stay_out`. Planted exit 101 in 0.843 s. Restored exit 0 in 0.515 s. Assertion: `src/../standin-runtime/mod.rs:545:9` `the stand-in leaves exhausted, revoked and expired grants out` left `{"req-exhausted", "req-expired", "req-live", "req-revoked"}` right `{"req-live"}`.

Old:

```text
    grant.life == Life::Live && visible(grant, caller)
```

New:

```text
    visible(grant, caller)
```

F-standin-ended-session. Named test `standin_shell_sees_every_live_grant`. Planted exit 101 in 0.749 s. Restored exit 0 in 0.733 s. Assertion: `src/../standin-runtime/mod.rs:257:9` `the stand-in lists every live grant` left `{"req-b", "req-z"}` right `{"req-a", "req-b", "req-z"}`.

Old:

```text
    let _ended = grant.session_ended;
    grant.life == Life::Live && visible(grant, caller)
```

New:

```text
    grant.life == Life::Live && !grant.session_ended && visible(grant, caller)
```

### Gates

The shared heavy-build lease was free (`fcntl.flock` acquired in 0.000 s) and released after the commands. `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.18 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 292.28 seconds. 117 passed, 0 failed, 14 ignored. The lib target passed 6 tests. The effects target passed 57 tests, with 12 ignored, in 220.72 seconds. The runtime target passed 10 tests, with 2 ignored, in 13.91 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:3` names the list route as an operation. Grant rows stay seeded fields. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:50` stores a seeded row and reads no clock, file, network or env. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:74` is the only list method. `kept` at line 110 is the one filter. |
| 4. Runtime core grows? | No | `src/lib.rs:9` points the lab module at `standin-runtime/`. `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:81` returns 400 for an unknown scope. Line 84 returns 403 for a client global view. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `standin-runtime/mod.rs:118` keeps the view in the lab value. This change adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:221` starts the six tests. Each plant above fails its named assertion and passes after restore. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:20` is the life the filter reads. `Caller` at line 12 is only the session argument. |

## 045 — RA-6 stand-in launches and lists resident instances

045: `StandIn::post_capsules` and `StandIn::get_capsules` extend the same `StandIn` for `POST /api/capsules` and `GET /api/capsules`. A shell launch of an admitted path answers `starting` with `session_id` equal to `id` before `finish_start`. The list then shows `running` or `failed` with the cause, and a failed entry stays until the test instant is 60 seconds after it failed. A client is refused with `This endpoint requires shell privileges`. `parallel_capsules_complete_independently` stays `#[ignore = "blocked: RT4"]`. A PASS here leaves the real Runtime's resident rows blocked. There is no new `falsifiers.json` id. `Cargo.toml` and `Cargo.lock` are unchanged.

Re-found and still at the cited lines. `35697329b:lab/resident-instances/SPEC.md:104` `world resident-capsule {`. `:131` `{"id": "...", "name": "...", "status": "starting", "session_id": "..."}`. `:155` `entry stays listed with its cause for at least 60 seconds.` `35697329b:lab/resident-instances/src/http.rs:249` `pub fn parse_instance(value: &Value) -> Result<Instance, String> {` and `:252` `session: text(value, "session_id")?.to_owned(),`. Today's `elastos/crates/elastos-server/src/api/routes.rs:100` is `"completed"`. `elastos/crates/elastos-compute/src/providers/component.rs:168` is `let id = CapsuleId::new(format!("component-{}", uuid::Uuid::new_v4()));` and `:352` is `session: self.capsule_id.clone(),`. `elastos/wit/elastos-bus-v1.wit:87` is `run: func() -> result<_, bus-error>;`. `elastos/crates/elastos-server/src/api/middleware.rs:93` is `"This endpoint requires shell privileges"`. `elastos/crates/elastos-server/src/api/server.rs:463` is `.route("/api/capsules", get(routes::list_capsules))`. `lab/agent-conformance/tests/effects.rs:20` is `#[ignore = "blocked: RT4"]`.

### Hand-run falsifiers

No list id. Each plant was restored before the next. Lib tests are `standin_runtime::tests::NAME`; a bare name with `--exact` runs nothing. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and lane `target/host` plus `target/host-build`. After the last restore, `standin-runtime/mod.rs` matched its pre-plant bytes (`sha256 1c249e36cedec5c02d1efca72b5bb88e477ca66b5f2b4666be8913bc7ee1fa06`). `git diff -- lab/agent-conformance/standin-runtime/mod.rs` is the candidate only. The plant expressions are absent from that file.

F-standin-launch-stub. Named test `standin_launch_returns_before_start`. Planted exit 101 in 1.224 s. Restored exit 0 in 0.723 s. Assertion: `src/../standin-runtime/mod.rs:977:9` `the stand-in returns starting and the Bus session before start finishes` left `id component-1, name read-shared, status completed` right `status starting` with `session_id component-1`.

Old:

```text
        require_shell(caller)?;
        let path = launch_path(body)?;
```

New:

```text
        return Ok(json!({
            "id": "component-1",
            "name": "read-shared",
            "status": "completed",
        }));
        require_shell(caller)?;
        let path = launch_path(body)?;
```

F-standin-early-running. Named test `standin_launch_returns_before_start`. Planted exit 101 in 1.178 s. Restored exit 0 in 0.669 s. Assertion: `src/../standin-runtime/mod.rs:972:9` `the stand-in returns starting and the Bus session before start finishes` left `status running` right `status starting`.

Old:

```text
        let phase = ResidentStatus::Starting;
```

New:

```text
        let phase = ResidentStatus::Running;
```

F-standin-one-id. Named test `standin_two_launches_are_two_instances`. Planted exit 101 in 0.811 s. Restored exit 0 in 0.947 s. Assertion: `src/../standin-runtime/mod.rs:1021:9` `the stand-in numbers the second launch component-2` left `component-1` right `component-2`.

Old:

```text
    fn mint_id(&mut self) -> String {
        let id = format!("component-{}", self.next_id);
        self.next_id += 1;
        id
    }
```

```text
        self.instances.push(Instance {
```

New:

```text
    fn mint_id(&mut self) -> String {
        format!("component-{}", self.next_id)
    }
```

```text
        self.instances.clear();
        self.instances.push(Instance {
```

F-standin-ok-is-failed. Named test `standin_start_ok_is_running`. Planted exit 101 in 1.217 s. Restored exit 0 in 0.936 s. Assertion: `src/../standin-runtime/mod.rs:1080:9` `the stand-in stores running with an empty cause when start returns ok` left `status failed` right `status running`.

Old:

```text
        Start::Ok => (ResidentStatus::Running, String::new(), None),
```

New:

```text
        Start::Ok => (ResidentStatus::Failed, String::new(), Some(instant)),
```

F-standin-expire-running. Named test `standin_start_ok_is_running`. Planted exit 101 in 1.213 s. Restored exit 0 in 0.945 s. Assertion: `src/../standin-runtime/mod.rs:1093:9` `the stand-in keeps a running instance at instant 60` left `Null` right `running`.

Old:

```text
        ResidentStatus::Starting | ResidentStatus::Running => true,
```

New:

```text
        ResidentStatus::Starting => true,
        ResidentStatus::Running => instant < FAILED_KEEP_SECS,
```

F-standin-bad-start. Named test `standin_bad_start_is_failed`. Planted exit 101 in 1.227 s. Restored exit 0 in 0.610 s. Assertion: `src/../standin-runtime/mod.rs:1119:13` `the stand-in lists a failed start with its cause` left `status running` cause `start refused` right `status failed`.

Old:

```text
        Start::Error(text) | Start::Trap(text) => {
            (ResidentStatus::Failed, text.clone(), Some(instant))
        }
```

New:

```text
        Start::Error(text) | Start::Trap(text) => {
            (ResidentStatus::Running, text.clone(), None)
        }
```

F-standin-drop-failed. Named test `standin_failed_stays_for_sixty_seconds`. Planted exit 101 in 1.218 s. Restored exit 0 in 1.019 s. Assertion: `src/../standin-runtime/mod.rs:1156:9` `the stand-in lists a failed instance at instant 0` left `Null` right `failed`.

Old:

```text
            Some(at) => instant.saturating_sub(at) < FAILED_KEEP_SECS,
```

New:

```text
            Some(at) => instant.saturating_sub(at) > 0
                && instant.saturating_sub(at) < FAILED_KEEP_SECS,
```

F-standin-keep-failed. Named test `standin_failed_stays_for_sixty_seconds`. Planted exit 101 in 1.172 s. Restored exit 0 in 0.692 s. Assertion: `src/../standin-runtime/mod.rs:1170:9` `the stand-in omits a failed instance at instant 60` left the failed entry right `{"capsules":[]}`.

Old:

```text
            Some(at) => instant.saturating_sub(at) < FAILED_KEEP_SECS,
```

New:

```text
            Some(at) => instant.saturating_sub(at) <= FAILED_KEEP_SECS,
```

F-standin-admit-skip. Named test `standin_unadmitted_path_is_refused`. Planted exit 101 in 1.222 s. Restored exit 0 in 0.670 s. Assertion: `src/../standin-runtime/mod.rs:878:9` `the stand-in refuses an unadmitted path` left `Ok` `status starting` `session_id component-1`.

Old:

```text
        Err(self.not_resident(path))
```

New:

```text
        Ok(("read-shared".to_owned(), Start::Ok))
```

F-standin-old-world. Named test `standin_unadmitted_path_is_refused`. Planted exit 101 in 1.189 s. Restored exit 0 in 0.975 s. Assertion: `src/../standin-runtime/mod.rs:878:9` `the stand-in refuses an unadmitted path` left `not a resident component: /capsules/read-shared world product-capsule-v1`.

Old:

```text
const RESIDENT_WORLD: &str = "resident-capsule";
```

New:

```text
const RESIDENT_WORLD: &str = "product-capsule-v1";
```

F-standin-launch-body. Named test `standin_launch_body_is_path_only`. Planted exit 101 in 1.220 s. Restored exit 0 in 0.965 s. Assertion: `src/../standin-runtime/mod.rs:826:9` `the stand-in refuses a launch body with no path` left `Ok` `status starting`.

Old:

```text
        require_shell(caller)?;
        let path = launch_path(body)?;
```

New:

```text
        require_shell(caller)?;
        let path = match launch_path(body) {
            Ok(path) => path,
            Err(_) => {
                return Ok(json!({
                    "id": "component-1",
                    "name": "read-shared",
                    "status": "starting",
                    "session_id": "component-1",
                }));
            }
        };
```

F-standin-start-twice. Named test `standin_start_returns_once`. Planted exit 101 in 0.916 s. Restored exit 0 in 0.969 s. Assertion: `src/../standin-runtime/mod.rs:1197:9` `the stand-in accepts start once` left `Ok(())`.

Old:

```text
        if instance.phase != ResidentStatus::Starting {
            return Err((400, "start already returned".to_owned()));
        }
```

New:

```text
        if instance.phase != ResidentStatus::Starting {
            instance.phase = ResidentStatus::Failed;
            instance.cause = "start already returned".to_owned();
            instance.failed_at = Some(instant);
            return Ok(());
        }
```

F-standin-rewrite-admit. Named test `standin_one_admit_per_path`. Planted exit 101 in 1.166 s. Restored exit 0 in 0.961 s. Assertion: `src/../standin-runtime/mod.rs:850:9` `the stand-in keeps the first admit` left `Ok(())`.

Old:

```text
        if self.admitted.iter().any(|row| row.path == path) {
            return Err((400, format!("resident path already admitted: {path}")));
        }
```

New:

```text
        if let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) {
            row.start = start;
            return Ok(());
        }
```

F-standin-client-capsules. Named test `standin_client_cannot_launch_or_list`. Planted exit 101 in 0.967 s. Restored exit 0 in 0.951 s. Assertion: `src/../standin-runtime/mod.rs:1233:9` `the stand-in refuses a client launch and list` left two `Ok` bodies, the launch `status starting` and the list holding that entry. `require_shell` was left in place.

Old:

```text
        require_shell(caller)?;
        let path = launch_path(body)?;
```

```text
        require_shell(caller)?;
        let mut listed: Vec<&Instance> = self
```

New:

```text
        let _ = caller;
        let path = launch_path(body)?;
```

```text
        let _ = caller;
        let mut listed: Vec<&Instance> = self
```

### Gates

The shared heavy-build lease was free (`fcntl.flock` acquired in 0.000 s) and released after the commands. `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun. The volume had about 30 GiB free.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.22 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 338.18 seconds. 127 passed, 0 failed, 14 ignored. The lib target passed 16 tests. The effects target passed 57 tests, with 12 ignored, in 248.68 seconds. The runtime target passed 10 tests, with 2 ignored, in 18.50 seconds. The report target passed 23 tests.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:197` takes `path` as the launch key and does not open it. The world at line 15 is the SPEC's proposed world name. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:186` stores the test instant and reads no clock. `admit_resident` at line 144 reads no directory. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:321` `require_shell` is the one client refusal. `status_text` at line 328 is the one status map. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and `LOG.md`. `src/lib.rs:9` still points the lab module there. `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:238` returns 400 for a path that was not admitted. `require_shell` at line 324 returns 403 for a client. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `standin-runtime/mod.rs:176` applies the test-supplied `Start`. This change adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:823` starts the ten resident tests. Each plant above fails its named assertion and passes after restore. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:144` admits a path. Launch mints `component-N` and does not call `seed_grant`. |

## 042 — Point the falsifier list at the one runner

042: Every live entry in `falsifiers.json` uses command `agent-conformance`, and every edit path is `../../lab/agent-conformance/` plus the same relative path. The list still has 87 ids. `F-ac2c` plants the `NotFound` arm of `Fixture::no_policy` so a missing policy file is treated as a grant of the one read. `fixtures/no-policy.json` stays absent. `Cargo.toml` and `Cargo.lock` are unchanged.

Path check, resolved from `examples/agent-host`: target_count 19; edits 91; distinct_files 19; missing 0; outside 0. Every edit path is an existing file, and its path relative to the repo is one of those 19 recovery targets.

`python3 -I examples/agent-host/falsify.py --from lab/agent-conformance/falsifiers.json --list` exited 0 and listed 87 ids.

One invocation of `python3 -I examples/agent-host/falsify.py --from lab/agent-conformance/falsifiers.json F-report-blocker-list F-ac1c F-ac2c F-agent-host-p7` took 184.915 seconds and exited 1. The runner's exit is the ignored test: `not as expected: F-agent-host-p7`. Verdict lines:

```text
baseline: 3 named tests pass without an edit, 1 do not
F-ac1c CAUGHT                            25s  take HOME from the parent instead of the fresh root
F-ac2c CAUGHT                            49s  a missing policy file is treated as a grant of the one read
F-report-blocker-list CAUGHT                            18s  keep only the first whitespace word of a blocker reason
F-agent-host-p7 NOT RUN                            0s  run the real agent-host P7 manifest gap before the UsersAI binding lands
       did not run without the edit: real_agent_host_journal_under_usersai_principal
summary: 3 CAUGHT, 1 NOT RUN of 4
not as expected: F-agent-host-p7
```

The first three are CAUGHT. `F-agent-host-p7` is NOT RUN with `did not run without the edit`. The other 83 ids were not run. There was no census rerun of `F-ac2c`.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. The shared heavy-build lease wait was 0.000 seconds before the falsifier run and 46.819 seconds before the gates. Both gate commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.294 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 465.326 seconds. 127 passed, 0 failed, 14 ignored.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `falsifiers.json:2` names the runner command and paths relative to `examples/agent-host`. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/common/grants.rs:45` still returns `false` when the policy file is missing. |
| 3. A second path or a second copy of one rule? | No | `RUNBOOK.md:412` applies `F-ac2c` with the one `agent-conformance` command. |
| 4. Runtime core grows? | No | The edit is `falsifiers.json`, `RUNBOOK.md`, `GAPS.md` and `LOG.md`. `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/common/grants.rs:39` keeps the `NotFound` arm and supplies zero entries. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `tests/effects.rs:275` calls `poll` only when `apply_policy` is true. This change adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `falsifiers.json:763` names `no_policy_file_does_not_mean_allow`. The runner reported `F-ac2c` CAUGHT. |
| 8. Identity, admission and allowance stay separate? | Yes | `tests/common/grants.rs:39` treats a missing file as zero entries. A grant still requires the flag at `tests/effects.rs:275`. |

## 043 — Declared network request is denied until a grant

043: The one probe manifest declares `localhost://Public/agent-conformance-grants/*` and `elastos://net/stream`. `ungranted_network_is_refused` uses the existing `exercise_read` controller. The pending request is denied with `fixture denies unlisted read`. The network arm still returns `Ok(())` on a grant and does not call `providers::invoke`. `F-ac8a` keeps its command, path, id, title, expect and tests; only its capabilities `old` and `new` change. `F-net-grant` has no list id. `Cargo.toml` and `Cargo.lock` are unchanged.

Baseline row, before the plant: `fixture read: exit:Some(1) matched:0 granted:0 denied:1 content_error:false` and `probe refusal effect:network exit:Some(1) reason_present:true`. Stderr carries `BusError::Denied("fixture denies unlisted read")` and does not carry `capsule manifest does not declare authority`.

`F-net-grant`, hand-run, three steps. Original `fixtures/grants.json` sha256 `3009a4dd9f0820ad07a60f4ecf2f15709161653ba598753d34f6ccd8ead1396b`:

```json
{
  "deny_reason": "fixture denies unlisted read",
  "grants": [
    {
      "resource": "localhost://Public/agent-conformance-grants/granted.txt",
      "action": "read",
      "reason": "agent conformance: fixture read",
      "duration": "once"
    }
  ]
}
```

Planted bytes, sha256 `a6c057ce4c56e49aeae31b27b7e2ff151b0af4edff922279531d0e6cc574c780`:

```json
{
  "deny_reason": "fixture denies unlisted read",
  "grants": [
    {
      "resource": "localhost://Public/agent-conformance-grants/granted.txt",
      "action": "read",
      "reason": "agent conformance: fixture read",
      "duration": "once"
    },
    {
      "resource": "elastos://net/stream",
      "action": "execute",
      "reason": "agent conformance: ungranted effect",
      "duration": "once"
    }
  ]
}
```

Planted `ungranted_network_is_refused` exited 101 in 19.210 seconds. The row saw `fixture read: exit:Some(0) matched:1 granted:1 denied:0 content_error:false` and failed `Some(0) == Some(1)`. Restored bytes matched the original. The same test then exited 0 in 25.007 seconds with `matched:0 granted:0 denied:1`.

`./lab/agent-conformance/run.sh` exited 0 in 254.783 seconds. Its table has `ungranted_network_is_refused | PASS` and no ` | FAIL` row.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`.

- Cold `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 864.932 seconds. The Runtime build inside the preceding network row was 256.80 seconds and the artifact tests were 575.17 seconds, so this command was outside the 600-second bound. 127 passed, 0 failed, 14 ignored.
- Warm gate, same environment, after those builds: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.143 seconds. `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` exit 0, real 272.013 seconds. 127 passed, 0 failed, 14 ignored. This pair is inside the 600-second bound. The census pair named in the task did not fail, so there was no census rerun.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `probe/capsule.json:15` adds the Bus resource `elastos://net/stream`. The launched probe stays the staged bundle hash. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/effects.rs:533` requires `granted:0` and line 534 requires `denied:1`. The probe does not open a stream. |
| 3. A second path or a second copy of one rule? | No | `tests/effects.rs:107` calls the one `exercise_read` controller. |
| 4. Runtime core grows? | No | The edit is the probe manifest, `tests/effects.rs`, `tests/artifact.rs`, `falsifiers.json`, `RUNBOOK.md`, `GAPS.md` and `LOG.md`. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/effects.rs:541` requires `BusError::Denied` with the fixture reason. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `probe/src/lib.rs:260` returns `Ok(())` from `capabilities::request` and does not call `providers::invoke`. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:106` is `ungranted_network_is_refused`. Hand-run `F-net-grant` exited 101 planted and 0 restored. |
| 8. Identity, admission and allowance stay separate? | Yes | `probe/capsule.json:15` lets the request become pending. `tests/effects.rs:534` still requires a separate deny. |

## 051 — Land the reviewed stand-in stop past the stdout leftover

051: `standin-runtime/mod.rs` and `standin-runtime/README.md` are the bytes from `438fb71f9bcdad43457746c7f3e20c0f83beedbb`, which match `3d8511be8269f446bf0726b049c64494cb12ad42` and `6b073a4710ee056b7007b8fb989d91238c51f413`. `git show 438fb71f9bcdad43457746c7f3e20c0f83beedbb:lab/agent-conformance/<path> | cmp - lab/agent-conformance/<path>` succeeded for both paths. `StandIn::delete_capsule` answers `DELETE /api/capsules/:id`. `stop_one`, `revoke_live`, `stop_reason`, `unknown_instance`, `not_live` and `keeps_instance` are present. `keep` is the one life filter. `fn delete_capsule` was absent on this base before the copy. `tests/runtime.rs`, `tests/effects.rs`, `tests/common/operator.rs`, `src/census.rs`, `RUNBOOK.md`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` stay as the base has them. A search of `lab/agent-conformance` finds none of `drain_capture_holders`, `capture_holder_only`, or `capture_holder_drain_retries_a_stdout_leftover`. There is no new `falsifiers.json` id. After the restore, `git diff 438fb71f9bcdad43457746c7f3e20c0f83beedbb -- lab/agent-conformance/standin-runtime` is empty.

### Hand-run falsifier

No list id. One plant, then the restore, before the gates. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_stop_sets_stopped -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The shared heavy-build lease wait was 0.000 seconds before the run.

F-standin-stop-stub. Named test `standin_stop_sets_stopped`. Planted exit 101 in 12.784 seconds. Restored exit 0 in 1.721 seconds. Assertion: `src/../standin-runtime/mod.rs:982:9` `the stand-in stores stopped with the stop reason`. Left status `running` with an empty cause. Right status `stopped` with cause `stopped: stop one`.

Old:

```text
        require_shell(caller)?;
        let reason = stop_reason(body)?;
```

New:

```text
        return Ok(Value::Null);
        require_shell(caller)?;
        let reason = stop_reason(body)?;
```

The plant is the start of `delete_capsule`. It returns `Ok` of null before any instance is read. After the restore, that return is absent.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The shared heavy-build lease wait was 0.000 seconds. `Cargo.toml` and `Cargo.lock` are unchanged. There was no second test run.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.205 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, real 266.246 seconds. The lib target passed 26 tests. The effects target finished 55 passed, 2 failed, 12 ignored, in 217.65 seconds. The failed tests were `runaway_trap_is_bounded_while_siblings_finish` at `tests/common/parallel.rs:88` and `ungranted_sibling_read_is_refused` at `tests/effects.rs:446`. Both census lines were `process leftover; processes:1 paths:["home/Library/Application Support/elastos/host-process.lock"]`. That path includes `host-process.lock`. The task stops on that shape. The stand-in files stayed the restored bytes. `operator.rs`, `src/census.rs`, `tests/effects.rs` and `tests/runtime.rs` stayed as the base has them.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:235` `delete_capsule` takes the instance id. It does not name code or content by a URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:265` `revoke_live` changes stored grant life. It opens no file, network, or `wasi` import. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:331` `keep` is the one life filter. `src/census.rs:79` `cleanup` stays the one cleanup. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md` and `LOG.md`. `src/lib.rs:9` still points the lab module there. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:451` returns 400 `unknown instance`. `:456` returns 400 `instance is not live`. `:372` returns 403 `This endpoint requires shell privileges`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `standin-runtime/mod.rs:247` `stop_one` updates stand-in state. This change adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:1449` `standin_stop_sets_stopped`. The planted return of null fails that assertion at `:982` and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:235` stops an instance and does not admit a path. `keep` at `:331` filters life and grants nothing. |

## 048 — One stand-in grant does not authorise the sibling

048: `StandIn::authorise` is a lab seam on the same `StandIn`. It refuses an unknown id, then a grant whose life is not `Live`, then a shell or another session, and it returns `Ok(())` for the owning client. `is_live` is the one life test. `keep` and `revoke_live` call it. The session decision calls `visible` and does not compare session ids itself. A stop still revokes that session through `revoke_live`, so the live view drops that grant and the sibling's own grant stays. `instance_grant_does_not_authorise_sibling` stays the process-isolation row. There is no new `falsifiers.json` id. `Cargo.toml` and `Cargo.lock` are unchanged.

> **A6.** Launch `read-shared` twice. Grant instance 1 only, and wait until it
> is `running`. The live-grant view shows exactly one grant, bound to instance 1.
> Instance 2's request for the same resource is still pending, in its own
> session. Deny it. Instance 2 ends `failed` with the denial in its cause, and
> instance 1 is still `running` with the same single grant. Stop instance 1. The
> census also requires zero live grants for both sessions.

This task takes the grant half of that paragraph: two launches, one grant bound to instance 1, instance 2 refused, instance 1 still running, then stop instance 1 and the live view has no grant for that session. The sentences about a pending request, a denial cause, and the process census are not this task. After the stop, instance 2's presentation of instance 1's grant is status 400 `grant is not live: Revoked`, because the life check runs before the caller check.

### Hand-run falsifiers

No list id. Each plant was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and lane `target/host` plus `target/host-build`. The shared heavy-build lease wait was 0.000 seconds. After the last restore, `standin-runtime/mod.rs` matched its pre-plant bytes (`sha256 90605e0f80988326f1bb9532384d2474accc2e04470e356b5ef02eb4ec5696d1`). `git diff -- lab/agent-conformance/standin-runtime/mod.rs` is the candidate only. The plant expressions are absent from that file.

F-standin-a6-stub. Named test `standin_sibling_cannot_use_the_grant`. Planted exit 101 in 1.194 seconds. Restored exit 0 in 1.607 seconds. The planted crate compiled. Assertion: `src/../standin-runtime/mod.rs:2134:9` `the stand-in refuses instance 1's grant for instance 2: Ok(())`. The inserted line shifts that assert from 2133 in the restored file.

Old:

```text
    pub fn authorise(&self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        let Some(grant) = self
```

New:

```text
    pub fn authorise(&self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        return Ok(());
        let Some(grant) = self
```

The plant is the start of `authorise`. It returns `Ok(())` before any grant is read.

F-standin-a6-sibling. Named test `standin_sibling_cannot_use_the_grant`. Planted exit 101 in 0.881 seconds. Restored exit 0 in 1.189 seconds. Assertion: `src/../standin-runtime/mod.rs:2133:9` `the stand-in refuses instance 1's grant for instance 2: Ok(())`. `visible` was left as it is.

Old:

```text
    !matches!(caller, Caller::Shell) && visible(grant, caller)
```

New:

```text
    !matches!(caller, Caller::Shell) && visible(grant, Caller::Shell)
```

The plant is that one call. The session decision treats every caller as the shell.

F-standin-a6-stop-keeps. Named test `standin_stop_clears_that_sessions_grant`. Planted exit 101 in 1.148 seconds. Restored exit 0 in 1.385 seconds. Assertion: `src/../standin-runtime/mod.rs:2115:9` `the stand-in refuses the stopped session's grant: Ok(())`.

Old:

```text
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
```

New:

```text
        if !is_live(grant.life) {
            return Ok(());
        }
```

`authorise` returns `Ok(())` for a grant whose life is not `Live`.

F-standin-a6-unknown. Named test `standin_authorise_unknown_grant`. Planted exit 101 in 0.917 seconds. Restored exit 0 in 1.476 seconds. Assertion: `src/../standin-runtime/mod.rs:2104:9` `the stand-in refuses unknown grant "" for shell: Ok(())`.

Old:

```text
            return Err(unknown_grant(request_id));
```

New:

```text
            return Ok(());
```

An unknown id, including `""`, is accepted.

F-standin-a6-life-skip. Named test `standin_authorise_dead_grants`. Planted exit 101 in 1.202 seconds. Restored exit 0 in 1.080 seconds. Assertion: `src/../standin-runtime/mod.rs:2112:9` `the stand-in refuses a grant that is not live before the caller check: Ok(())`. The plant removes three lines, so the restored assert is at 2115.

Old:

```text
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
        if !session_authorises(grant, caller) {
```

New:

```text
        if !session_authorises(grant, caller) {
```

The life check is gone, so a dead grant falls through to the caller.

F-standin-a6-caller-first. Named test `standin_authorise_dead_grants`. Planted exit 101 in 1.303 seconds. Restored exit 0 in 1.463 seconds. Assertion: `src/../standin-runtime/mod.rs:2115:9` `the stand-in refuses a grant that is not live before the caller check: Err((403, "wrong capsule: expected component-1, got component-2"))`.

Old:

```text
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
```

New:

```text
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
```

The caller check runs before the life check.

F-standin-a6-shell. Named test `standin_shell_cannot_authorise`. Planted exit 101 in 0.916 seconds. Restored exit 0 in 1.461 seconds. Assertion: `src/../standin-runtime/mod.rs:2133:9` `the stand-in refuses a shell presentation of a live grant: Ok(())`.

Old:

```text
    !matches!(caller, Caller::Shell) && visible(grant, caller)
```

New:

```text
    visible(grant, caller)
```

The shell refusal is removed. `visible` was left as it is.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. The shared heavy-build lease wait was 0.000 seconds. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.135 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 306.142 seconds. 142 passed, 0 failed, 14 ignored. The lib target passed 31 tests. The effects target passed 57 tests, with 12 ignored, in 234.04 seconds. The runtime target passed 10 tests, with 2 ignored, in 14.23 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:146` `authorise` takes the caller and the request id. It does not name code or content by a URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:147` reads `self.grants`. The method is `&self` and opens no file, network, or `wasi` import. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:360` `is_live` is the one life test. `:373` calls `visible` and does not compare session ids. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and `LOG.md`. `src/lib.rs:9` still points the lab module there. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:487` returns 400 `unknown grant:`. `:500` returns 400 `grant is not live:`. `:504` returns 403 `wrong capsule:`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `standin-runtime/mod.rs:146` decides from stored grants. This change adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:2146` `standin_sibling_cannot_use_the_grant`. The planted `return Ok(())` fails that assertion and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:147` reads grants and does not read instances. `admit_resident` at `:166` still admits a path on its own. |

## 049 — A12: a stopped stand-in run leaves no live grant

049: `standin_a12_census` reads the shell `all_sessions_live` view, passes that body to the one grader `grants::live_grant_state`, reads the shell capsule list, and then returns the one physical census `census::cleanup`'s `Err` or `Ok(())` only for a line with `root checks PASS`. `standin_stopped_run_leaves_no_live_grant` admits `/capsules/read-shared` twice, starts both, seeds `req-1` on `component-1` and `req-2` on `component-2`, stops both, and proves the empty live view, the `stopped` entries and the physical census. A second stand-in with no seed proves the live-status refusal. The test uses one `ThrowawayHome` and one free `127.0.0.1:0` port. It adds no `StandIn` method, no second life filter and no second session compare. `fn live_grant_state` becomes `pub(super) fn live_grant_state`; its body is unchanged. `falsifiers.json` gains `F-standin-a12-stub`, `F-standin-a12-skip-status` and `F-standin-a12-skip-cleanup`. `standin-runtime/mod.rs`, `src/census.rs`, `src/report.rs` and `GAPS.md` are unchanged. `run_leaves_no_live_grant` stays `#[ignore = "blocked: AC-021-GRANTS"]`. `Cargo.toml` and `Cargo.lock` are unchanged.

The journey, read only at `35697329be0aad89eb68d0adf78aa94d24751317:lab/resident-instances/SPEC.md`:

> **A12.** Launch `read-shared` twice, grant both, and wait for both `running`.
> The pending view saw both requests, and the live-grant view shows a grant for
> each session. These are the census's positive controls. Stop both. The census
> then requires zero live grants as well.

> **Census.** No launched instance is `starting`, `running` or `stopping`. No
> pending request comes from a journey session. In A6 and A12, no live grant
> belongs to a journey session. No process below the operator pid is new since
> the baseline. `GET /api/health` is still ok.

This task takes the grant view and the instance-status check, plus the socket and file census that stays with this lane. The pending-request sentences and the operator process-tree walk are not this task. The test asserts the stand-in did the work. It scores no A12 on the real Runtime.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects standin_stopped_run_leaves_no_live_grant -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true` and lane `target/host` plus `target/host-build`. After the last restore, the full gate passed and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` printed nothing. Each planted run retained its throwaway root; those three roots were removed after this record. Each plant compiled.

F-standin-a12-stub. Planted exit 101 in 1.78 seconds. Restored exit 0 in 1.73 seconds. Assertion: `tests/effects.rs:1169:5` `the stand-in keeps the seeded grants live before the stops: Ok(())`.

Old:

```text
fn standin_a12_census(standin: &StandIn, home: &ThrowawayHome, port: u16) -> Result<(), String> {
```

New:

```text
fn standin_a12_census(standin: &StandIn, home: &ThrowawayHome, port: u16) -> Result<(), String> {
    return Ok(());
```

The start of `standin_a12_census` returns `Ok(())` before the grant list is read.

F-standin-a12-skip-status. Planted exit 101 in 1.57 seconds. Restored exit 0 in 1.73 seconds. Assertion: `tests/effects.rs:1179:5` `the stand-in refuses a running instance in the census: Ok(())`.

Old:

```text
        if status == "starting" || status == "running" || status == "stopping" {
```

New:

```text
        if false && (status == "starting" || status == "running" || status == "stopping") {
```

The live-status condition never refuses a `running` instance.

F-standin-a12-skip-cleanup. Planted exit 101 in 1.46 seconds. Restored exit 0 in 1.73 seconds. Assertion: `tests/effects.rs:1221:5` `the stand-in refuses the temp leftover: Ok(())`.

Old:

```text
    match census::cleanup(home, port) {
```

New:

```text
    match Ok::<String, String>("root checks PASS".to_owned()) {
```

The physical census call is replaced by a passing string.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`. Both commands stayed inside 600 seconds. The locked suite passed on the first run, so there was no census rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 260.95 seconds. The effects target passed 58 tests, 0 failed, 12 ignored, in 203.63 seconds. The runtime target passed 10 tests, 0 failed, 2 ignored, in 16.77 seconds. The report target passed 23 tests.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `tests/effects.rs:1070` reads the shell live view. The seeded resource is a Public path, not a code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The change is test code on the lab stand-in. It opens one loopback port and one throwaway home. |
| 3. A second path or a second copy of one rule? | No | `tests/common/grants.rs:1628` is the one grant grader. `tests/effects.rs:1091` calls the one physical census `census::cleanup`. `standin-runtime/mod.rs` keeps its one life filter. |
| 4. Runtime core grows? | No | No `elastos/` or `capsules/` edit. The stand-in stays in its lab folder. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/effects.rs:1087` returns `instance still live: <status>`, and `:1091` returns the census `Err` line. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The test seeds the stand-in and adds no capsule import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:1099` `standin_stopped_run_leaves_no_live_grant`. Each of the three plants fails that named test and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | `tests/effects.rs:1138` seeds a grant per session, and `:1184` stops an instance through `delete_capsule`. The grant view and the instance list stay separate reads. |

### Gate failure after submission, and the one allowed rerun

The supervisor's `test` check ran `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0` and exited 101. The effects target reported 57 passed, 1 failed, 12 ignored in 235.96 seconds. The only failure was `agent_cannot_read_human_space_without_grant`, and its census line was `cleanup census: FAIL retained:target/home-79868-1793107816321670000-2; process leftover; processes:1 paths:["stdout-6"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)`. That is acceptance 6's allowed case: an allowed named test and a process-leftover path matching `stdout-<digits>`. The root stayed at `lab/agent-conformance/target/home-79868-1793107816321670000-2`.

The rerun used the same command and environment, with lane `target/host` and `target/host-build`, and exited 101 in 283.36 seconds. The effects target reported 57 passed, 1 failed, 12 ignored in 230.81 seconds. `standin_stopped_run_leaves_no_live_grant` passed. The only failure was `process_isolation::parallel_instances_complete_independently`, at `tests/common/parallel.rs:88:14`, with `cleanup census: FAIL retained:target/home-68200-1793108400375307000-168; process leftover; processes:1 paths:["home/Library/Application Support/elastos/host-process.lock"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)`. That test name and that path are outside acceptance 6's allowed list, so the rerun failed and work stops here. The retained roots are `lab/agent-conformance/target/home-68200-1793108400375307000-168` through `-172`. No live holder remained on either retained root when inspected after the runs. No census or operator edit was made.

### Fixture read-bound fix, and the passing gate

A later supervisor `test` check exited 101 in `grants::tests::client_session_credentials_are_guarded`. The test expected `Err("invalid fixture authorization header")` and got `Err("could not bound fixture read")` at `tests/common/grants.rs:2641:21`. The one `http` read loop set the read timeout again on every iteration. After the peer closed the connection, that repeated `set_read_timeout` could fail under load, so the invalid status token never reached `remember_capability`.

The fix in `http` sets one read timeout per response, retries `Interrupted`, and keeps the total bound with a post-read deadline check. Each refusal keeps its own string: `could not bound fixture read` only for a non-interrupted or repeated set failure, and `fixture HTTP response exceeded its bound` after the deadline. The synthetic test now reaches the expected token refusal. This is a second `tests/common/grants.rs` change beyond `pub(super) fn live_grant_state`; the gate failure required it. `fn live_grant_state` and its body stay as specified.

Old:

```text
    let mut bytes = Vec::new();
    loop {
        let remaining = bound
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("fixture HTTP response exceeded its bound")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "could not bound fixture read")?;
        let mut chunk = [0; 4096];
        let size = stream
            .read(&mut chunk)
            .map_err(|_| "fixture response read failed")?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > 1024 * 1024 {
            return Err("fixture HTTP response exceeded size bound");
        }
    }
```

New:

```text
    let read_bound = bound
        .checked_sub(started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or("fixture HTTP response exceeded its bound")?;
    let mut attempts = 0;
    while let Err(error) = stream.set_read_timeout(Some(read_bound)) {
        if error.kind() != std::io::ErrorKind::Interrupted || attempts == 2 {
            return Err("could not bound fixture read");
        }
        attempts += 1;
    }
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let size = stream
            .read(&mut chunk)
            .map_err(|_| "fixture response read failed")?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > 1024 * 1024 {
            return Err("fixture HTTP response exceeded size bound");
        }
        if started.elapsed() >= bound {
            return Err("fixture HTTP response exceeded its bound");
        }
    }
```

The failing test passed 10 standalone runs in a row after the fix, 0.16 to 0.18 seconds each.

Gates after the fix, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`, lane `target/host` and `target/host-build`:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 281.08 seconds. The effects target passed 58 tests, 0 failed, 12 ignored in 215.18 seconds; `grants::tests::client_session_credentials_are_guarded` and `standin_stopped_run_leaves_no_live_grant` passed. The runtime target passed 10 tests, 0 failed, 2 ignored in 14.53 seconds. The process-isolation target passed 9 tests. The report target passed 23 tests. The artifact target passed 7 tests. The build target passed 1 test. The lib target passed 31 tests. The probe unit target passed 3 tests.

No `Cargo.toml` or `Cargo.lock` change.

### Review repair: the `http` change is reverted

The review failed the section above. Acceptance 1 lets `tests/common/grants.rs` change only `fn live_grant_state` to `pub(super) fn live_grant_state`. `grants::tests::client_session_credentials_are_guarded` is not on acceptance 6's rerun list, so that failure was a stop, not a reason to edit the shared fixture. The new code also broke the 2-second bound: it set the read timeout once, so a server that sent one byte just before the deadline let the next `read` wait about 2 seconds more, and the overrun then read as `fixture response read failed` instead of `fixture HTTP response exceeded its bound` (P11).

The `http` read loop is restored byte for byte to the "Old" block above: each `read` gets only the time left, and `could not bound fixture read` comes from the per-read `set_read_timeout`. `fn live_grant_state` stays `pub(super)` and its body is unchanged. So `git diff -U0 -- lab/agent-conformance/tests/common/grants.rs` against 048's merge shows one hunk again.

The `client_session_credentials_are_guarded` failure (`Err("could not bound fixture read")` where `Err("invalid fixture authorization header")` was expected, `tests/common/grants.rs:2641`) is left for its own task. That task needs a test that fails without its fix, a loopback server that drips one byte every 1.5 s and must get `fixture HTTP response exceeded its bound` within about 2.1 s, and a falsifier id. It is not 049's.

## 052 — A10: a stand-in stop settles that session's pending requests

052: `StandIn` gains one request store beside `grants`. `seed_request` is the lab seam that stores one pending record. `get_capability_requests` answers `GET /api/capability/requests?session=`. It reuses `require_shell`, then refuses a missing or empty session, then returns that session's records sorted by `request_id`. `stop_one` calls `settle_pending` once, after `revoke_live`, with the stored `stopped: ` cause. `settle_pending` changes only that session's `Pending` records to `Denied`, sets `settled_by` to `runtime`, and writes the cause to `decision_reason`. It leaves `request_id`, `session_id`, `resource`, `action` and `reason`. `finish_start` does not settle. `delete_capsule`, `revoke_live`, `keep`, `visible` and `authorise` keep their signatures and bodies, except the one `stop_one` cause line now names a local `cause` so the same text reaches both the instance and its requests. No method reads the clock, the disk or a WIT file. There is no second request route, no second deny function and no HTTP server. There is no new `falsifiers.json` id. `Cargo.toml` and `Cargo.lock` are unchanged.

### Quote from the resident SPEC (read only)

> RI-5 Runtime settlement and the request record
>
> When an instance stops or fails, the Runtime denies each of its pending
> requests within the bound. The denial reason names the end: it contains the
> stop reason, or the failure cause.
>
> The shell reads a session's requests, pending or settled, with a new shell-only
> route:
>
> ```text
> GET /api/capability/requests?session=<session_id>
> ```
>
> ```json
> {"requests": [{"request_id": "...", "session_id": "...", "resource": "...",
>                "action": "read", "reason": "...", "status": "denied",
>                "decision_reason": "instance stopped: ...",
>                "settled_by": "runtime"}]}
> ```
>
> `status` is `pending`, `granted`, `denied` or `expired`. `settled_by` is
> `shell` or `runtime`, and `null` only while pending. A session's records stay
> readable for at least 60 seconds after its instance ends.

### Quote of the two journey functions (read only)

```rust
pub fn a10_cancel_one_instance<R: ResidentRuntime>(rt: &mut R) -> Outcome {
    run(rt, |j| {
        let (a, b) = j.launch_pair(Fixture::ReadShared, Fixture::ReadShared)?;
        let ra = j.wait_request(&a)?;
        let rb = j.wait_request(&b)?;
        j.stop(&a, CANCEL_REASON)?;
        j.runtime_settlement(&a, Some(&ra), CANCEL_REASON)?;
        j.together(&[&b], State::live, "live", "after instance-1 was cancelled")?;
        if !j.still_pending(&rb)? {
            return Err(format!(
                "the pending request from {} was settled when {} was cancelled",
                b.label, a.label
            ));
        }
        j.grant(&rb)?;
        j.wait_state(&b, State::Running)?;
        j.watch(&a, &State::Stopped)?;
        j.together(
            &[&b],
            |state| *state == State::Running,
            "running",
            "after the watch",
        )?;
        j.stop(&b, CLEANUP_REASON)?;
        let census = j.census(false)?;
        Ok(format!(
            "A10: instance-1 stopped mid-request with the cancel reason; the Runtime denied its pending request naming the stop; no request from it for {}s; instance-2 kept its own request, got its grant and kept running; {census}",
            WATCH.as_secs()
        ))
    })
}
```

```rust
    fn runtime_settlement(
        &mut self,
        of: &Launched,
        seen: Option<&Request>,
        mention: &str,
    ) -> Result<RequestRecord, String> {
        let what = format!("the Runtime's settlement of the request from {}", of.label);
        let record = self.wait(STATE_BOUND, &what, |rt| {
            let records = rt.requests(&of.session)?;
            match records.as_slice() {
                [] => Ok(None),
                [one] if one.status == Status::Pending => Ok(None),
                [one] => Ok(Some(one.clone())),
                more => Err(format!(
                    "{} has {} request records; the fixture makes one",
                    of.label,
                    more.len()
                )),
            }
        })?;
        if record.request.session != of.session {
            return Err(format!(
                "the request records for {} name another session",
                of.label
            ));
        }
        fixture_request(&record.request, of)?;
        if seen.is_some_and(|request| request.id != record.request.id) {
            return Err(format!(
                "the settled record for {} is not the request that was pending",
                of.label
            ));
        }
        if self.decided.contains(&record.request.id) {
            return Err(format!(
                "the harness decided the request from {}; this check needs the Runtime's own settlement",
                of.label
            ));
        }
        if record.status != Status::Denied {
            return Err(format!(
                "the request from {} ended {:?}; the Runtime must deny it when the instance ends",
                of.label, record.status
            ));
        }
        if record.settled_by != Some(Actor::Runtime) {
            return Err(format!(
                "the request from {} was settled by {:?}, not by the Runtime",
                of.label, record.settled_by
            ));
        }
        if mention.is_empty() || !record.decision.contains(mention) {
            return Err(format!(
                "the Runtime's denial for {} reads {:?}, which omits {:?}",
                of.label, record.decision, mention
            ));
        }
        if self.rt.pending()?.iter().any(|r| r.session == of.session) {
            return Err(format!("a request from {} is still pending", of.label));
        }
        Ok(record)
    }
```

### The settlement

`settle_pending` is the one deny path for a stop. It runs from the accepted arm of `stop_one` only, after `revoke_live`, and receives the same `stopped: ` cause text the instance stores. A refused stop returns before that call. `finish_start` stores `failed` with its cause and calls no settlement. `get_capability_requests` filters no record by age, so a denied record stays readable at `set_instant(60)`.

### Tests

The lib target has ten new tests in `standin_runtime::tests`:

- `standin_stop_denies_that_sessions_pending`: two running instances, a pending request for each, a live grant on instance 1, and one stop. The stopped session's record is one `denied` entry with `settled_by` `runtime` and `decision_reason` `stopped: stop one`. The shell live view has no grant and the request list has no `req-g`. The sibling request stays pending. The denied entry is still returned at instant 60. A second stand-in with two requests and the reason `cancel the run` proves every pending record is denied, sorted, with that cause.
- `standin_stop_leaves_the_siblings_request`: the same stop leaves `req-2` pending with `settled_by` null, and instance 2 stays `running`.
- `standin_failed_start_leaves_the_request`: `Start::Error("start refused")` and `Start::Trap("start trapped")` each leave the request pending and store the failed cause.
- `standin_requests_are_shell_only`: a client read is 403 for a valid, missing and empty session. A shell read with no session or an empty session is 400 `requests need a session`. A valid shell read returns the record.
- `standin_duplicate_request_is_refused`: a second seed of `req-1` with different fields is 400 `request already stored: req-1`. The first record stays pending and no replacement record exists.
- `standin_request_seed_validation`: each empty required field is 400 with the one reason and stores nothing. An empty `reason` is accepted and stored as `""`.
- `standin_request_record_contract`: the body's only key is `requests`. Each entry has the eight keys. Two records are sorted, hold the complete pending values, and another session's record stays out. An unknown session is `{"requests":[]}`.
- `standin_refused_stop_preserves_requests`: client, malformed-body, unknown-instance and empty-id refusals leave the record pending. The ended-instance refusal also leaves a request seeded after the accepted stop pending.
- `standin_stop_preserves_settled_requests`: a fixture record that is already `denied` and settled by `shell` keeps its values through an accepted stop, which denies only the new pending record.
- `standin_starting_stop_denies_that_sessions_pending`: an accepted stop during `starting` denies the starting instance's pending request.

### Hand-run falsifiers

No list id. Each plant was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. The planted crate compiled every time. After the last restore, `standin-runtime/mod.rs` matched its pre-plant bytes (`sha256 28ce9afa7247fbbe6466920819de1bcb89a25465e198c9d0c2ad32df26955d1b`) and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only. The plant expressions are absent from that file.

F-standin-a10-stub. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 1.231 seconds. Restored exit 0 in 0.645 seconds. Assertion: `src/../standin-runtime/mod.rs:1995:9` `assertion left == right failed: the stand-in denies the stopped instance's pending request and names the stop`. The record stayed `pending` with no settler.

Old:

```text
    fn settle_pending(&mut self, session_id: &str, cause: &str) {
        for request in &mut self.requests {
```

New:

```text
    fn settle_pending(&mut self, session_id: &str, cause: &str) {
        return;
        for request in &mut self.requests {
```

F-standin-a10-sibling. Named test `standin_stop_leaves_the_siblings_request`. Planted exit 101 in 0.996 seconds. Restored exit 0 in 0.680 seconds. Assertion: `src/../standin-runtime/mod.rs:2064:9` `assertion left == right failed: the stand-in leaves the sibling's request pending`. The sibling's request was `denied` with `stopped: stop one`.

Old:

```text
            if request.session_id == session_id && request.status == RequestStatus::Pending {
```

New:

```text
            if request.status == RequestStatus::Pending {
```

F-standin-a10-blank-reason. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 1.092 seconds. Restored exit 0 in 1.048 seconds. Assertion: `src/../standin-runtime/mod.rs:1994:9` `assertion left == right failed: the stand-in denies the stopped instance's pending request and names the stop`. The record had `status` `denied` and `decision_reason` `""`.

Old:

```text
                request.decision_reason = cause.to_owned();
```

New:

```text
                request.decision_reason = String::new();
```

F-standin-a10-fail-settles. Named test `standin_failed_start_leaves_the_request`. Planted exit 101 in 1.156 seconds. Restored exit 0 in 1.087 seconds. Assertion: `src/../standin-runtime/mod.rs:2101:13` `assertion left == right failed: the stand-in leaves the request pending when start fails with start refused`.

Old:

```text
        let (phase, cause, ended_at) = apply_start(&instance.start, instant);
        instance.phase = phase;
        instance.cause = cause;
        instance.ended_at = ended_at;
        Ok(())
```

New:

```text
        let (phase, cause, ended_at) = apply_start(&instance.start, instant);
        instance.phase = phase;
        instance.cause = cause;
        instance.ended_at = ended_at;
        if phase == ResidentStatus::Failed {
            let id = instance.id.clone();
            let cause = instance.cause.clone();
            self.settle_pending(&id, &cause);
        }
        Ok(())
```

The other plants cover the read, seed, record, refusal and guard rules that the spec check names.

F-standin-a10-read-shell. Named test `standin_requests_are_shell_only`. Planted exit 101 in 1.081 seconds. Assertion: `src/../standin-runtime/mod.rs:2121:13`. `require_shell` is removed from `get_capability_requests`, so a client read succeeds.

Old:

```text
    pub fn get_capability_requests(
        &self,
        caller: Caller<'_>,
        session: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let Some(session) = session.filter(|session| !session.is_empty()) else {
```

New:

```text
    pub fn get_capability_requests(
        &self,
        caller: Caller<'_>,
        session: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        let Some(session) = session.filter(|session| !session.is_empty()) else {
```

F-standin-a10-read-order. Named test `standin_requests_are_shell_only`. Planted exit 101 in 1.137 seconds. Assertion: `src/../standin-runtime/mod.rs:2122:13`. The query check runs first, so a client with no session gets 400 instead of 403.

Old:

```text
        require_shell(caller)?;
        let Some(session) = session.filter(|session| !session.is_empty()) else {
            return Err((400, "requests need a session".to_owned()));
        };
        let mut listed: Vec<&Request> = self
```

New:

```text
        let Some(session) = session.filter(|session| !session.is_empty()) else {
            return Err((400, "requests need a session".to_owned()));
        };
        require_shell(caller)?;
        let mut listed: Vec<&Request> = self
```

F-standin-a10-seed-id / -session / -resource / -action. Named test `standin_request_seed_validation`. Planted exits 101 in 0.873, 1.286, 0.880 and 0.931 seconds. Assertion for each: `src/../standin-runtime/mod.rs:1236:9` in the one refusal helper; the refused field then passed into storage. The restored condition is one expression:

```text
        if request_id.is_empty()
            || session_id.is_empty()
            || resource.is_empty()
            || action.is_empty()
        {
```

Each plant removed one disjunct and kept the other three, for example:

```text
        if session_id.is_empty() || resource.is_empty() || action.is_empty() {
```

F-standin-a10-duplicate. Named test `standin_duplicate_request_is_refused`. Planted exit 101 in 0.988 seconds. Assertion: `src/../standin-runtime/mod.rs:2148:9`. The duplicate check is removed.

Old:

```text
        if self
            .requests
            .iter()
            .any(|request| request.request_id == request_id)
        {
            return Err((400, format!("request already stored: {request_id}")));
        }
        self.requests.push(Request {
```

New:

```text
        self.requests.push(Request {
```

F-standin-a10-record-key. Named test `standin_request_record_contract`. Planted exit 101 in 1.185 seconds. Assertion: `src/../standin-runtime/mod.rs:686:9` in `assert_keys`. The entry gains a `duration` key.

Old:

```text
        "settled_by": request.settled_by,
    })
```

New:

```text
        "settled_by": request.settled_by,
        "duration": "once",
    })
```

F-standin-a10-record-session. Named test `standin_request_record_contract`. Planted exit 101 in 0.893 seconds. Assertion: `src/../standin-runtime/mod.rs:2242:9`. The session filter is replaced, so another session's record appears.

Old:

```text
            .filter(|request| request.session_id == session)
```

New:

```text
            .filter(|request| !request.request_id.is_empty())
```

F-standin-a10-record-order. Named test `standin_request_record_contract`. Planted exit 101 in 1.269 seconds. Assertion: `src/../standin-runtime/mod.rs:2242:9`. The sort runs in reverse order.

Old:

```text
        listed.sort_by(|left, right| left.request_id.cmp(&right.request_id));
```

New:

```text
        listed.sort_by(|left, right| right.request_id.cmp(&left.request_id));
```

F-standin-a10-record-pending. Named test `standin_request_record_contract`. Planted exit 101 in 1.382 seconds. Assertion: `src/../standin-runtime/mod.rs:2242:9`. A seeded pending record carries a non-empty `decision_reason`.

Old:

```text
            status: RequestStatus::Pending,
            decision_reason: String::new(),
            settled_by: None,
```

New:

```text
            status: RequestStatus::Pending,
            decision_reason: "seeded".to_owned(),
            settled_by: None,
```

F-standin-a10-one-request. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 0.947 seconds. Assertion: `src/../standin-runtime/mod.rs:2043:9`. The second pending request stays `pending`.

Old:

```text
                request.decision_reason = cause.to_owned();
            }
```

New:

```text
                request.decision_reason = cause.to_owned();
                break;
            }
```

F-standin-a10-fields. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 1.028 seconds. Assertion: `src/../standin-runtime/mod.rs:1995:9`. The settled record loses its `resource`.

Old:

```text
                request.settled_by = Some("runtime");
                request.decision_reason = cause.to_owned();
```

New:

```text
                request.settled_by = Some("runtime");
                request.resource = String::new();
                request.decision_reason = cause.to_owned();
```

F-standin-a10-settler. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 1.311 seconds. Assertion: `src/../standin-runtime/mod.rs:1994:9`. The settler reads `shell`.

Old:

```text
                request.settled_by = Some("runtime");
```

New:

```text
                request.settled_by = Some("shell");
```

F-standin-a10-discard. Named test `standin_stop_denies_that_sessions_pending`. Planted exit 101 in 1.145 seconds. Assertion: `src/../standin-runtime/mod.rs:2028:9` at the instant-60 read. A denied record drops out at 60 seconds.

Old:

```text
            .filter(|request| request.session_id == session)
```

New:

```text
            .filter(|request| {
                request.session_id == session
                    && !(self.instant >= FAILED_KEEP_SECS
                        && request.status == RequestStatus::Denied)
            })
```

F-standin-a10-early-settle. Named test `standin_refused_stop_preserves_requests`. Planted exit 101 in 0.862 seconds. Assertion: `src/../standin-runtime/mod.rs:2350:9`. The ended instance's new request was denied before the phase check.

Old:

```text
        let phase = self.instances[index].phase;
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
        let session_id = self.instances[index].id.clone();
```

New:

```text
        let phase = self.instances[index].phase;
        let session_id = self.instances[index].id.clone();
        self.settle_pending(&session_id, "stopped: planted");
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
```

F-standin-a10-guard. Named test `standin_stop_preserves_settled_requests`. Planted exit 101 in 1.150 seconds. Assertion: `src/../standin-runtime/mod.rs:2378:9`. The settled record is rewritten.

Old:

```text
            if request.session_id == session_id && request.status == RequestStatus::Pending {
```

New:

```text
            if request.session_id == session_id {
```

F-standin-a10-starting. Named test `standin_starting_stop_denies_that_sessions_pending`. Planted exit 101 in 1.455 seconds. Assertion: `src/../standin-runtime/mod.rs:2408:9`. A stop during `starting` settles nothing.

Old:

```text
        self.revoke_live(&session_id);
        self.settle_pending(&session_id, &cause);
```

New:

```text
        self.revoke_live(&session_id);
        if phase == ResidentStatus::Running {
            self.settle_pending(&session_id, &cause);
        }
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.144 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 286.42 seconds. This was the first gate run and it passed inside the 600-second bound. The visible targets were the report target 23 passed, the runtime target 10 passed with 2 ignored, the probe unit target 3 passed, and both doc-test targets 0. The earlier targets ran before those, so the run reached the end with no failure line. The per-target counts on the later counting run were the lib target 41 passed, the report binary 1 passed, the artifact target 7 passed, the build target 1 passed, the effects target 58 passed with 12 ignored, the harness target 9 passed and the report target 23 passed.

Two confirmation runs of the same command then failed one test each. Neither test touches this slice and each passes alone. The failures are recorded here because they are real runs:
- Counting run: exit 101, real 275.52 seconds. The only failure was `grant_refused_from_another_session` in `tests/effects.rs`. Alone: exit 0 in 9.82 seconds.
- Clean-pass attempt: exit 101, real 286.19 seconds. The only failure was `cleanup_census_refuses_each_leftover` in `tests/runtime.rs`. Alone: exit 0 in 1.61 seconds.

No `Cargo.toml` or `Cargo.lock` change. The filtered output did not keep the census lines for those two failures; each failing test passes alone without a leftover in its own census.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:155` `seed_request` takes the shell's request text. `:196` `get_capability_requests` filters by session id. Neither names code or content by a URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:387` reads and writes the stand-in's request store. The methods open no file, network or `wasi` import, and the shell route grants nothing. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:387` `settle_pending` is the one deny path and `stop_one` at `:371` calls it once. `:201` `require_shell` is reused. `:208` is the one session filter. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and `LOG.md`. `src/lib.rs:9` still points the lab module there. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:170` returns 400 `request needs an id, a session, a resource and an action`. `:178` returns 400 `request already stored:`. `:201` calls `require_shell`, whose `:528` returns 403 `This endpoint requires shell privileges`. `:203` returns 400 `requests need a session`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `standin-runtime/mod.rs:387` decides from stored records. This change adds no capsule import and no Runtime call. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:1983` `standin_stop_denies_that_sessions_pending`. The planted early return fails its assertion at `:1995` and the restored test passes. Twenty-two plants cover the ten new tests. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:356` `stop_one` stops an instance and settles its requests; it does not admit a path. `:155` `seed_request` stores a request and creates no grant. |

The real A10 row stays blocked. `standin_stop_denies_that_sessions_pending` is the lab stand-in, and a PASS there gives the Runtime no A10 credit.

## 053 — Stand-in is the one contract other lanes call

053: `tests/standin_contract.rs` is the one new Rust file. It adds `standin_matches_ra1_fields` and `standin_matches_ra6_states`, both call `agent_conformance::standin_runtime::StandIn`, and neither builds a second grant list, status map or JSON builder. `standin-runtime/README.md` gains a final `## Callers` section and `RUNBOOK.md` gains one paragraph. `standin-runtime/mod.rs`, `src/lib.rs`, `Cargo.toml` and `Cargo.lock` keep their bytes.

### Quote from RA-1: Smallest change (read only)

> 1. Add one read-only method on `CapabilityManager` that answers "can this token
>    still be used now?". It reads the store the manager already owns: epoch,
>    individual revocation, use count against `max_uses`, and the token's own
>    expiry. A handler cannot do this today. The store field is private and the
>    manager has two public getters, neither of which reads use counts or
>    revocations (`manager.rs:95`, `:641`, `:646`).
> 2. In `list_capabilities`, when the caller is a shell session and asks for the
>    global view, list every `Granted` request that passes that test. Add
>    `"scope": "all_sessions_live"` to the response, and add the session id to
>    each entry (today's entry type has none). Every other caller keeps today's
>    own-session list.
>
> This touches two crates, `elastos-runtime` (the method) and `elastos-server`
> (the handler and the response marker). It adds no route if the query form is
> used.

### Quote from RA-6: Smallest change (read only)

> The SPEC extends existing routes (Principle 10). Each part, from its evidence:
>
> - **RI-1.** Add a `resident` interface (`start`, `stop`) and a world that
>   exports it, beside `product-capsule-v1` in `elastos/wit/`. Bind it in the
>   component provider. Select it by the manifest ABI. Check the validator
>   (`component.rs:76`) against the new function names.
> - **RI-2.** For a resident component, spawn `start` and return after admission
>   with the activation id and session (`component.rs:168`, `:352`). Keep the
>   bridge principal and manifest bounds registered until the instance ends.
>   Today the launch clears them when `start` returns (`runtime.rs:320`, `:324`).
> - **RI-3.** Call `register_capsule` from the launch. Add `session_id` and
>   `cause` to `RunningCapsuleInfo` and to the list answer. Keep a stopped or
>   failed entry for the retention the SPEC states.
> - **RI-4.** Accept a reason on `DELETE /api/capsules/:id`. Give the component
>   provider a real stop. The engine uses fuel only, and the activation record
>   holds no interrupt handle (`component.rs:83`, `:32-35`). A guest inside a
>   request wait must also end (`resource_bridge.rs:1008`). The stop then revokes
>   the session's grants and settles its pending requests (RA-2).
>
> The SPEC fixes only what A3, A6, A10, A11 and A12 observe. It leaves events,
> streams, restart and the full Bus v2 operation set to Elacity issues 181 and
> 463.

### Plants

No list id. Each plant ran one at a time, compiled, and was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test standin_contract NAME -- --exact`. After the last restore and before the gates, `standin-runtime/mod.rs` matched its pre-plant bytes (`sha256 28ce9afa7247fbbe6466920819de1bcb89a25465e198c9d0c2ad32df26955d1b`) and `git diff -- lab/agent-conformance/standin-runtime/mod.rs lab/agent-conformance/src/lib.rs lab/agent-conformance/Cargo.toml lab/agent-conformance/Cargo.lock` printed 0 lines.

F-standin-contract-stub. Named test `standin_matches_ra1_fields`. Old bytes at the start of `get_capability_list`:

```rust
    ) -> Result<Value, (u16, String)> {
        if let Some(scope) = scope {
```

New bytes:

```rust
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "scope": "all_sessions_live", "capabilities": [] }));
        if let Some(scope) = scope {
```

Planted exit 101 in 1.89 seconds. The planted crate compiled with the unreachable-code warning. Assertion: `tests/standin_contract.rs:29:5` (`assert_keys`) from the client body call at `tests/standin_contract.rs:84`, message `the stand-in did the work: the client body is the capability list`; left `{"capabilities", "scope"}`, right `{"capabilities"}`. The stub's empty shell bodies still match the empty view, so the plain client body is the first assertion to fail. Restored, the named test passed in 0.00 seconds.

F-standin-contract-field. Named test `standin_matches_ra1_fields`. Old bytes in `entry`:

```rust
    fields.insert("request_id".to_owned(), json!(grant.request_id));
    if include_session {
        fields.insert("session_id".to_owned(), json!(grant.session_id));
    }
    fields.insert("resource".to_owned(), json!(grant.resource));
```

New bytes:

```rust
    fields.insert("request_id".to_owned(), json!(grant.request_id));
    fields.insert("resource".to_owned(), json!(grant.resource));
```

Planted exit 101 in 1.32 seconds. The planted crate compiled with the unused-parameter warning. Assertion: `tests/standin_contract.rs:29:5` (`assert_keys`) from the shell entry call at `tests/standin_contract.rs:151`, message `the stand-in did the work: the shell entry carries the six RA-1 fields`; left `{"action", "duration", "granted_at", "request_id", "resource"}`, right `{"action", "duration", "granted_at", "request_id", "resource", "session_id"}`. Restored, the named test passed.

F-standin-contract-state. Named test `standin_matches_ra6_states`. Old bytes in `post_capsules`:

```rust
        let phase = ResidentStatus::Starting;
```

New bytes:

```rust
        let phase = ResidentStatus::Running;
```

Planted exit 101 in 1.36 seconds. The planted crate compiled. Assertion: `tests/standin_contract.rs:231:5`, message `the stand-in did the work: the launch answers starting before start returns`; left `String("running")`, right `"starting"`. Restored, the named test passed in 0.00 seconds.

### Gates

`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` passed. `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` passed with exit 0 in 296.67 seconds (`real`): 155 passed, 0 failed, 14 ignored across 12 targets, including both contract tests in `tests/standin_contract.rs`. `Cargo.toml` and `Cargo.lock` keep their bytes. No census leftover appeared, so the single rerun rule did not apply.

## 054 — Undeclared network stays refused and the denial names it

054: `assert_refusal` takes the staged manifest bytes, and `undeclared_network_manifest_is_refused` stages `MANIFEST` with `elastos://net/stream` removed and requires the manifest refusal to name that resource. The one fixture reason assignment names a pending `elastos://net/stream` denial; read denials keep `fixture denies unlisted read`. `F-net-undeclared` and `F-net-reason` join `falsifiers.json`. `probe/capsule.json`, `probe/src/lib.rs`, `fixtures/grants.json`, `fixtures/instance-grants.json`, `standin-runtime/`, `src/`, `Cargo.toml` and `Cargo.lock` are unchanged.

### The two network rows

`assert_refusal` (`tests/effects.rs:40`) now takes the manifest bytes and passes them to `identity::stage_probe` at `tests/effects.rs:56`. The four earlier callers pass `MANIFEST`. The body lives in `assert_refusal_as` (`tests/effects.rs:46`) so the stripped bundle carries its own version identity label: a manifest copy that differs from `MANIFEST` is a different bundle, and its lab CID differs. The label `undeclared-network` keeps the report's one identity per effect name, so the declared row and the undeclared row each report their own bundle. The launch bound is 40 seconds because the probe's own pending wait is 30 seconds; a declared request under a plant reports its Bus reason instead of the harness bound.

`undeclared_network_manifest_is_refused` (`tests/effects.rs:132`) sits immediately after `ungranted_network_is_refused` (`:127`). It builds `Effect::Network`, removes only `elastos://net/stream` from the manifest capabilities, keeps the Public read capability, and requires exit 1 with `Component capsule denied: BusError::Internal("capsule manifest does not declare authority for elastos://net/stream")`. It starts no fixture controller and grants nothing. Stderr carries no `fixture denies` text.

The one reason assignment at `tests/common/grants.rs:811` denies a pending request whose `resource` is `elastos://net/stream` with `fixture denies unlisted elastos://net/stream`. Every other non-matching request keeps `self.fixture.deny_reason`. `exercise_read` (`tests/effects.rs:593`) expects that network reason; sibling and other read denials still expect `controller.deny_reason()`. The network row printed `fixture read: exit:Some(1) matched:0 granted:0 denied:1 content_error:false` and `probe refusal effect:network exit:Some(1) reason_present:true`.

Baseline from the one `./run.sh`: `undeclared_network_manifest_is_refused | PASS` and `ungranted_network_is_refused | PASS`. The undeclared bundle reported `{"effect":"undeclared-network","component_sha256":"67d2826de27d33930f60f5a26228fe1bb45946e8be8e4e462adac25103abfc3e","bundle_lab_cid":"bafybeiauhszbqfxoeg7ix4kerbt2jwk4ag234i3jllg5eudw245tqza6qi"}`; the declared row reported its own CID `bafybeiepnu6etnumpqea7vly37hhy55vvdxbbb4r4fpeipsqymubys3jdy`.

Docs: `RUNBOOK.md:147` and `GAPS.md:528` name the declared row's fixture reason; `RUNBOOK.md:148` is the new undeclared bullet; `RUNBOOK.md:293-294` and `GAPS.md:414-415` record the one network exception. Read-row sentences keep `fixture denies unlisted read`.

### Hand-run falsifiers

Both entries are appended after `F-standin-a12-skip-cleanup` in `falsifiers.json` (`F-net-undeclared` at `:1485`, `F-net-reason` at `:1501`). Each `old` occurs once in its file after `cargo fmt`. Each plant was restored before the next; `diff` against the recovered pre-plant bytes was empty after each restore. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects TEST -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. Each planted crate compiled and ran the named test.

F-net-undeclared. Named test `undeclared_network_manifest_is_refused`. Planted exit 101 in 36.98 seconds, test result 1 failed. Assertion: `tests/effects.rs:110:5` `expected nonzero exit and lifecycle refusal Internal("capsule manifest does not declare authority for elastos://net/stream")`; the declared manifest left the request pending, so `reason_present:false`. Restored exit 0 in 9.77 seconds.

Old:

```text
agent_conformance::identity::stage_probe(&home, &bytes, manifest, label)
```

New:

```text
agent_conformance::identity::stage_probe(&home, &bytes, MANIFEST, label)
```

F-net-reason. Named test `ungranted_network_is_refused`. Planted exit 101 in 15.19 seconds, test result 1 failed. Assertion: `tests/effects.rs:597:13` `the network denial names the network resource`. Restored exit 0 in 10.54 seconds.

Old:

```text
                let reason = if field(request, "resource")? == "elastos://net/stream" {
                    "fixture denies unlisted elastos://net/stream".to_owned()
                } else {
                    self.fixture.deny_reason.clone()
                };
```

New:

```text
                let reason = self.fixture.deny_reason.clone();
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. No census line failed, so no rerun was needed.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.139 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 261.107 seconds, inside the 600-second bound. 156 passed, 0 failed, 14 ignored across 12 targets; effects passed 59 with 12 ignored.
- One `./lab/agent-conformance/run.sh`: exit 0, real 261.427 seconds. Both network rows are PASS and no row is FAIL.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `tests/effects.rs:132` stages a bundle whose identity stays the `capsule_identity::checked_bundle` lab CID; the new test names the Bus resource, not code or content by URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `tests/effects.rs:132` starts no fixture controller and grants nothing. `probe/src/lib.rs` is unchanged. |
| 3. A second path or a second copy of one rule? | No | One staging call at `tests/effects.rs:56`, one reason assignment at `tests/common/grants.rs:811` and one `deny` at `:841`. `assert_refusal` delegates to `assert_refusal_as`. |
| 4. Runtime core grows? | No | The edit is `tests/effects.rs`, `tests/common/grants.rs`, `falsifiers.json`, `RUNBOOK.md`, `GAPS.md` and `LOG.md`. `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/effects.rs:593` requires `Denied("fixture denies unlisted elastos://net/stream")`; the undeclared row requires `Internal("capsule manifest does not declare authority for elastos://net/stream")`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The probe still requests through `capabilities::request` and returns on refusal, with no provider invoke. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:132` is the new named test; `F-net-undeclared` failed at `:110` and `F-net-reason` failed at `:597`. |
| 8. Identity, admission and allowance stay separate? | Yes | The undeclared row exercises admission (manifest declaration) alone and creates no grant; the declared row exercises the separate fixture denial. |

## 055 — Two agent components stay resident in one stand-in

055: `standin_two_agent_components_stay_resident` (`standin-runtime/mod.rs:1500`) admits `/capsules/agent-a` as `agent-a` and `/capsules/agent-b` as `agent-b` on one `StandIn`. It launches each path once, so the launch ids are `component-1` and `component-2` with `session_id` equal to each id and each name from that path's admit row. One list shows both `starting`, then both `running`, and instant 60 still shows both `running`. A stop of `component-1` with `{"reason":"stop one"}` returns null, stores `stopped: stop one`, and leaves `component-2` `running` as `agent-b`. `post_capsules`, `get_capsules`, `finish_start`, `delete_capsule`, `admit_resident`, `keep` and `visible` keep their bytes; no method is added. `standin_two_launches_are_two_instances` (`:1442`) still launches `/capsules/read-shared` twice and stops at `starting`. The new test uses one `StandIn` and no operator, probe build or second stand-in type.

### Quote from the A3 journey (read only, `35697329be0aad89eb68d0adf78aa94d24751317:lab/resident-instances/SPEC.md`)

> **A3.** Launch `read-shared` twice. Wait for one pending read from each
> session. In one list snapshot both instances are live. Grant both for their
> sessions. Both reach `running`. After the dwell, one snapshot still shows both
> `running`, so `start` returned and they stayed resident. No new process
> appeared below the operator. Stop both, then run the census.

This task takes the two-component pair, the one list, the dwell at instant 60 and one stop that leaves the sibling. The pending-request, grant, process-tree and census sentences are A6, A10 and A12.

### Hand-run plants

No `falsifiers.json` id. Each plant ran one at a time and was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_two_agent_components_stay_resident -- --exact`. Each planted crate compiled (the stub and empty plants each with a warning), and the named test failed on its assertion. After the last restore the named test passed (`1 passed; 0 failed`), and `git diff --numstat -- lab/agent-conformance/standin-runtime/mod.rs` is `142 0`: only the new test, its four path/name constants and `agent_body` are added.

F-standin-a3-stub. Named test `standin_two_agent_components_stay_resident`.

Old:

```text
        require_shell(caller)?;
        let path = launch_path(body)?;
```

New:

```text
        require_shell(caller)?;
        return Ok(json!({
            "id": "component-1",
            "name": "agent-a",
            "status": "running",
            "session_id": "component-1",
        }));
        let path = launch_path(body)?;
```

Planted exit 1 in 1.86 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:1524:9`, `the stand-in numbers the agent-b launch component-2`; left `String("component-1")`, right `"component-2"`. The stub also stored no instance and read no admit. Restored, the named test passed.

F-standin-a3-empty. Named test `standin_two_agent_components_stay_resident`.

Old:

```text
        require_shell(caller)?;
        let mut listed: Vec<&Instance> = self
```

New:

```text
        require_shell(caller)?;
        return Ok(json!({ "capsules": [] }));
        let mut listed: Vec<&Instance> = self
```

Planted exit 1 in 1.52 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:1539:9`, `the stand-in lists both agent components starting after both launches`; left `{"capsules":[]}`, right the two `starting` entries. Restored, the named test passed.

F-standin-a3-one-name. Named test `standin_two_agent_components_stay_resident`.

Old:

```text
        let path = launch_path(body)?;
        let (name, start) = self.admitted_start(path)?;
```

New:

```text
        let path = launch_path(body)?;
        let (_, start) = self.admitted_start(path)?;
        let name = self.admitted[0].name.clone();
```

Planted exit 1 in 1.33 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:1535:9`, `the stand-in names the agent-b launch from its admitted path`; left `String("agent-a")`, right `"agent-b"`. Restored, the named test passed. `delete_capsule`, `finish_start`, `admit_resident`, `keep` and `visible` are unchanged by the plants.

### Docs

`standin-runtime/README.md:37` is the new paragraph before `## Callers`. It keeps the RA-1 section and the RI-1 to RI-4 section, and states that `agent-a` and `agent-b` are two admitted components on one `StandIn`, that one list shows both `running` with distinct ids, and that instant 60 still shows both, with the M1-R replacement sentence, no A3 credit, the RT4 ignore and the 045 row for two launches of one path. `RUNBOOK.md:715` is the new paragraph after the last stand-in paragraph. `GAPS.md`, `falsifiers.json` and `falsify.py` are unchanged; so are `Cargo.toml` and `Cargo.lock`.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.168 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 339.377 seconds, inside the 600-second bound. 157 passed, 0 failed, 14 ignored across 12 targets. The lib target passed 42, including `standin_two_agent_components_stay_resident`; the effects target passed 59 with 12 ignored. No census line and no listed flaky test failed, so the single-rerun rule did not apply.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:1500` admits the two fixture paths `/capsules/agent-a` and `/capsules/agent-b` as lab records and names no code or content by URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | The test reads and writes the stand-in's in-memory `admitted` and `instances`; it starts no route, opens no file or network, and grants nothing. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:307` `post_capsules`, `:329` `get_capsules` and `:344` `delete_capsule` are reused as found; `:397` `mint_id` is the one id source. No method and no status map are added. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and `LOG.md`. `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | No new refusal surface. The reused stop path refuses a non-live instance with 400 `instance is not live: <status>` at `:637` and an unknown id with 400 `unknown instance: <id>` at `:607`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The test decides from stored records; `standin-runtime/mod.rs:585` `apply_start` is the one start outcome arm and imports no capsule or `wasi:*`. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:1500` is the new named test; the three plants failed at `:1524`, `:1539` and `:1535`. |
| 8. Identity, admission and allowance stay separate? | Yes | `standin-runtime/mod.rs:254` `admit_resident` stores the path name and the `Start`; the launch at `:307` reads that row and the stop at `:344` changes only one instance's phase and cause. |

The real A3 row stays blocked. `standin_two_agent_components_stay_resident` is the lab stand-in, and a PASS there gives the Runtime no A3 credit. `parallel_capsules_complete_independently` stays `#[ignore = "blocked: RT4"]`.

## 056 — A9: stand-in storage follows the selected Home

056: `StandIn::storage_for_home` (`standin-runtime/mod.rs:132`) is the one new associated function. It returns the selected Home's data directory plus `storage`, refuses the fixed shared temp path, and creates nothing. The data directory comes from `crate::harness::data_dir` (`src/harness.rs:16`) through the call at `standin-runtime/mod.rs:149`; the function does not call `dirs::data_dir` and does not copy `inside` or `directories_only`. `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `GAPS.md`, `Cargo.toml`, `Cargo.lock`, `probe/`, `falsify.py` and `falsifiers.json` keep their bytes. `standin-runtime/mod.rs` is not a recovery target and gains no `falsifiers.json` id; the three plants below ran by hand.

### Quote from the ask (read only, `513988ebd:lab/runtime-asks/03-launcher-storage-under-home.md`)

> ## Smallest change
>
> In `run_cmd.rs`, replace the three calls (`:62`, `:70`, `:236`) with
>
> ```rust
> let runtime = crate::create_runtime(crate::default_data_dir().join("storage")).await?;
> ```
>
> This is the expression `capsule_cmd.rs:149` already uses. One file, three
> lines, no new flag.

> - **Per-Home, not per-instance.** Two `run` clients of one Home now share
>   `<data dir>/storage`. They shared `/tmp/elastos/storage` before. The two
>   labs reach separate directories by giving each client its own Home. agent-
>   conformance already does this for its two-instance journeys.

The stand-in applies that path join and the one Mac rule; `elastos/` keeps its bytes.

### Refusals

The function refuses with status 400 in this order. An empty Home, a relative Home, or a Home whose components include `.` or `..` reads `storage needs a selected Home` (`:138-145`). A Home equal to `/tmp/elastos/storage` reads `shared temp directory is not agent storage`, before `data_dir` runs (`:146-148`). Any other Home is `data_dir(home)` joined with `storage` (`:149-150`). A `data_dir` error is status 400 with that function's text (`:149`). A joined path equal to `/tmp/elastos/storage` reads the shared reason (`:151-153`).

### Tests

- `standin_storage_follows_the_selected_home` (`standin-runtime/mod.rs:3195`) takes two `ThrowawayHome::new` values. Each `storage_for_home(home.home())` is `Ok` and equals `home.data().join("storage")`; that path does not exist; the two paths differ; a second call with the first Home returns the same path; both `finish()` are `Ok`. The three refused Homes are `` "", "standin-a9" and `/var/standin-a9/../other`, each status 400 with `storage needs a selected Home`.
- `standin_shared_temp_storage_is_refused` (`:3242`) refuses `/tmp/elastos/storage` with status 400 and `shared temp directory is not agent storage`, and asserts that the path's existence is unchanged. It deletes nothing and reads no contents.

### Hand-run plants

No `falsifiers.json` id. Each plant ran one at a time and was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact`. Each planted crate compiled and the named test failed on its assertion; after the restore the named test passed. Retained throwaway roots from the failed runs were removed.

F-standin-a9-stub. Named test `standin_storage_follows_the_selected_home`.

Old:

```text
        const SHARED_REASON: &str = "shared temp directory is not agent storage";

        let refused = |reason: &str| Err((400, reason.to_owned()));
```

New:

```text
        const SHARED_REASON: &str = "shared temp directory is not agent storage";

        return Ok(PathBuf::from(SHARED_TEMP));
        let refused = |reason: &str| Err((400, reason.to_owned()));
```

Planted exit 1 in 3.14 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3205:13` (one line added above the restored `assert_eq!` at `:3204`), `the stand-in returns the selected Home's data directory plus storage`; left `"/tmp/elastos/storage"`, right `target/home-.../home/Library/Application Support/elastos/storage`. Restored, the named test passed.

F-standin-a9-skip-rule. Named test `standin_storage_follows_the_selected_home`.

Old:

```text
        let data = crate::harness::data_dir(home).map_err(|reason| (400, reason.to_owned()))?;
        let storage = data.join("storage");
```

New:

```text
        let storage = home.join("storage");
```

Planted exit 1 in 2.81 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3203:13` (one line removed above the restored `assert_eq!` at `:3204`), `the stand-in returns the selected Home's data directory plus storage`; left `target/home-.../home/storage`, right `target/home-.../home/Library/Application Support/elastos/storage`. Restored, the named test passed.

F-standin-a9-shared-temp. Named test `standin_shared_temp_storage_is_refused`.

Old:

```text
        if home == Path::new(SHARED_TEMP) {
            return refused(SHARED_REASON);
        }
        let data = crate::harness::data_dir(home).map_err(|reason| (400, reason.to_owned()))?;
```

New:

```text
        let data = crate::harness::data_dir(home).map_err(|reason| (400, reason.to_owned()))?;
```

Planted exit 1 in 1.94 seconds (`real`), test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3243:9` (three lines removed above the restored `assert!` at `:3246`), `the stand-in refuses the fixed shared temp path before the Home rule: Ok("/tmp/elastos/storage/Library/Application Support/elastos/storage")`. Restored, the named test passed.

After the restores, `git diff --numstat -- lab/agent-conformance/standin-runtime/mod.rs` is `94 0`: the path import, `storage_for_home`, its doc comment and the two tests.

### Docs

`standin-runtime/README.md:39` is the new paragraph before `## Callers`. The file keeps the RA-1 field-lock sentence and the resident RI-1 to RI-4 material as found. The paragraph states that launcher storage is the selected Home's data directory plus `storage`, that the data directory comes from `harness::data_dir`, that `/tmp/elastos/storage` is refused and is not created, and that one Home has one directory; it gives the M1-R replacement sentence, no A9 credit, the `AC-006-STORAGE` ignore and the later `root-symlink-swap` and `host-hardlink` slice. `RUNBOOK.md:717` is the new paragraph after the last stand-in paragraph; every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.20 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 363.63 seconds, inside the 600-second bound. 159 passed, 0 failed, 14 ignored across 12 targets. The lib target passed 44, including both new tests; the effects target passed 59 with 12 ignored. No census line and no listed flaky test failed, so the single-rerun rule did not apply.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:132` joins a directory from the one Home rule and names no code or content by name or URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:132-155` creates no directory and opens no file; the test writes no grant and starts no route. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:149` calls `crate::harness::data_dir` (`src/harness.rs:16`); it calls no `dirs::data_dir`, copies neither `inside` nor `directories_only`, and adds no storage type. |
| 4. Runtime core grows? | No | The edit is `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and `LOG.md`; `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | A missing or dotted Home is 400 `storage needs a selected Home` (`:138`), the fixed shared path is 400 `shared temp directory is not agent storage` (`:146`), a `data_dir` error is 400 with its text (`:149`), and a joined shared path is 400 with the shared reason (`:151`). |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The seam only joins a path; it imports no capsule, no `wasi:*` and no Bus route. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:3195` and `:3242` are the named tests; the three plants failed at `:3205`, `:3203` and `:3243`. |
| 8. Identity, admission and allowance stay separate? | Yes | `storage_for_home` reads no grant, no capsule list and no clock, at `:132-155`; admission stays in `admit_resident` and allowance unchanged. |

The real A9 row stays blocked. `standin_storage_follows_the_selected_home` is the lab stand-in, and a PASS there gives the Runtime no A9 credit. `operator_storage_is_under_throwaway_home` stays `#[ignore = "blocked: AC-006-STORAGE"]` with its panic body, and `root-symlink-swap` and `host-hardlink` stay a later slice.

## 057 — A9: stand-in refuses the two named storage cases

057: `StandIn::confirm_storage` (`standin-runtime/mod.rs:163`) is the one new associated function. It calls `storage_for_home` (`:132`) and then `crate::harness::directories_only` (`src/harness.rs:37`) and creates nothing. The one link-count check is the private `one_link` (`standin-runtime/mod.rs:185`). `src/harness.rs` gains one word: `fn directories_only` becomes `pub(crate) fn directories_only`, and `git diff -U0` shows that one line only. `storage_for_home` keeps its body. `src/census.rs`, `tests/effects.rs`, `GAPS.md`, `Cargo.toml`, `Cargo.lock`, `probe/`, `falsify.py`, `falsifiers.json` and `lab/owned-storage` keep their bytes. `standin-runtime/mod.rs` is not a recovery target and gains no `falsifiers.json` id; the three plants below ran by hand and each was restored before the next.

The two refused cases are `root-symlink-swap` and `host-hardlink`. Their case ids come from `15d337dc9:lab/review-a9-290/REVIEW.md`, read only; no other cell of those rows is quoted.

### Refusals

`confirm_storage(home, entry)` refuses with status 400 in this order. `storage_for_home`'s error passes through unchanged (`standin-runtime/mod.rs:168`). `directories_only(storage, home)` false reads `storage directory is a symbolic link` (`:169-171`). An empty entry returns that storage path (`:172-174`). Any other entry whose components are not exactly one `Component::Normal` reads `storage entry stays under the selected Home` (`:175-179`). `one_link` on the joined path (`:180-181`, `:185-203`) returns `Ok(())` when the path is absent and when it is a regular file whose link count is 1. A regular file whose link count is above 1 reads `storage file has more than one link`; any other file type, including a symbolic link, reads `storage file is not a single regular file`. The check uses `symlink_metadata` and `nlink`; it reads no file bytes and follows no link, and `confirm_storage` calls no `create_dir`, `create_dir_all` or file create.

### Tests

- `standin_storage_refuses_root_symlink_swap` (`standin-runtime/mod.rs:3339`): one `ThrowawayHome`. Before a link exists, `confirm_storage(home.home(), "")` is `Ok` and equals `storage_for_home(home.home())`, and that path does not exist. The test makes that path a symbolic link with `std::os::unix::fs::symlink`; the link's own name is the storage path. `confirm_storage(home.home(), "")` is status 400 with `storage directory is a symbolic link`, and `symlink_metadata` on that path still reports a symbolic link. `home.finish()` is `Ok`. The test reads no link target and no file.
- `standin_storage_refuses_host_hardlink` (`:3374`): one `ThrowawayHome`. The test creates the storage directory, and `confirm_storage(home.home(), "absent.txt")` is `Ok` with the joined path. It creates one regular file `entry.txt`; `confirm_storage(home.home(), "entry.txt")` is `Ok` and equals that file. It adds a second name with `std::fs::hard_link`, so the link count is above 1. `confirm_storage` for `entry.txt` and for `second.txt` are each status 400 with `storage file has more than one link`. `confirm_storage(home.home(), "..")` and `confirm_storage(home.home(), "a/b")` are each status 400 with `storage entry stays under the selected Home`. `home.finish()` is `Ok`. The test reads no file.

### Hand-run plants

No `falsifiers.json` id. Each plant ran one at a time and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact`. Each planted crate compiled (unused-item warnings only) and the named test failed on its assertion; after the restore the named test passed. Retained throwaway roots from the failed runs were removed. After the restores, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows no plant.

F-standin-a9-link-stub. Named test `standin_storage_refuses_root_symlink_swap`.

Old:

```text
        let storage = Self::storage_for_home(home)?;
        if !crate::harness::directories_only(&storage, home) {
```

New:

```text
        let storage = Self::storage_for_home(home)?;
        return Ok(storage);
        if !crate::harness::directories_only(&storage, home) {
```

Planted exit 1, test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3361:9`, `the stand-in did the work: it refuses a storage directory that is a symbolic link: Ok("target/home-.../home/Library/Application Support/elastos/storage")`. Restored, the named test passed.

F-standin-a9-skip-link. Named test `standin_storage_refuses_root_symlink_swap`.

Old:

```text
        let storage = Self::storage_for_home(home)?;
        if !crate::harness::directories_only(&storage, home) {
            return Err((400, LINK_REASON.to_owned()));
        }
        if entry.is_empty() {
```

New:

```text
        let storage = Self::storage_for_home(home)?;
        if entry.is_empty() {
```

Planted exit 1, test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3357:9`, `the stand-in did the work: it refuses a storage directory that is a symbolic link: Ok("target/home-.../home/Library/Application Support/elastos/storage")`. Restored, the named test passed.

F-standin-a9-skip-nlink. Named test `standin_storage_refuses_host_hardlink`.

Old:

```text
                if meta.nlink() > 1 {
                    return Err((400, MANY_REASON.to_owned()));
                }
```

New:

```text
                if meta.nlink() > 1 {
                    return Ok(());
                }
```

Planted exit 1, test result FAILED. Assertion: `src/../standin-runtime/mod.rs:3400:13`, `the stand-in did the work: it refuses the hard-linked file under name "entry.txt": Ok("target/home-.../home/Library/Application Support/elastos/storage/entry.txt")`. Restored, the named test passed.

### Docs

`standin-runtime/README.md:39` stops after the `AC-006-STORAGE` ignore sentence. `:41` is the new paragraph before `## Callers`: `confirm_storage` calls `storage_for_home` and `directories_only`, a symbolic link at the storage directory is refused and not followed, a regular file under it whose link count is above 1 is refused and not read, with the M1-R replacement sentence, no A9 credit and the `AC-006-STORAGE` ignore. The file keeps the RA-1 section and the resident RI-1 to RI-4 section as found. `RUNBOOK.md:719` is the new paragraph after the last stand-in paragraph: `standin_storage_refuses_root_symlink_swap` is this stand-in, and a PASS there gives the Runtime no A9 credit. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.12 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 308.98 seconds, inside the 600-second bound. 161 passed, 0 failed, 14 ignored across the targets. The lib target passed 46, including both new tests; the effects target passed 59 with 12 ignored. No census line and no listed flaky test failed, so the single-rerun rule did not apply.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:163-182` joins a directory from the one Home rule and names no code or content by name or URL. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:163-203` creates no directory, writes no file and reads no file bytes; the tests start no route. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:168` calls the one `crate::harness::directories_only` (`src/harness.rs:37`); `one_link` is the one link-count check and copies no walk. |
| 4. Runtime core grows? | No | The edits are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md`, `LOG.md` and the visibility word in `src/harness.rs`; `elastos/` is unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | A storage symlink is 400 `storage directory is a symbolic link` (`:169-171`), an entry outside one normal component is 400 `storage entry stays under the selected Home` (`:175-179`), a linked file is 400 `storage file has more than one link`, and another file type is 400 `storage file is not a single regular file` (`:185-203`). |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The seam only checks a path under the selected Home; it imports no capsule, no `wasi:*` and no Bus route. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:3339` and `:3374` are the named tests; the three plants failed at `:3361`, `:3357` and `:3400`. |
| 8. Identity, admission and allowance stay separate? | Yes | `confirm_storage` reads no grant, no capsule list and no clock at `:163-203`; admission stays in `admit_resident` and allowance unchanged. |

The real A9 row stays blocked. `root-symlink-swap` and `host-hardlink` are refused by this lab stand-in, and a PASS gives the Runtime no A9 credit. `operator_storage_is_under_throwaway_home` stays `#[ignore = "blocked: AC-006-STORAGE"]` with its panic body.

## 058 — A11: a failed stand-in start settles its pending request

058: `finish_start` stores the phase, cause and `ended_at` as before, then calls the existing `settle_pending` once when that phase is `Failed`, with that session and the stored cause. `Start::Error` and `Start::Trap` both reach that one call. `Start::Ok` returns before it. An unknown id, a stop and a second `finish_start` return before it. `settle_pending`'s body and `stop_one` are unchanged. There is no second deny function, no second record renderer and no new Bus call. `seed_request` still stores the pending record while the instance is `starting`. No grant is minted from a pending request. The module header and the README settlement clause now state the failed-start rule. There is no new `falsifiers.json` id. `GAPS.md`, `falsify.py`, `src/census.rs`, `tests/effects.rs`, `probe/` and `Cargo.toml`/`Cargo.lock` are unchanged.

### Quote from the resident SPEC (read only)

> **A11.** Launch `fail-after-submit` and `read-shared`. Instance 1 ends
> `failed` with a cause. Its one request record is `denied`, settled by the
> Runtime, with the failure cause in its decision, and the harness never decided
> it. Nothing from instance 1 is pending. Grant instance 2; it reaches
> `running`. For the watch, instance 1 makes no request and stays `failed`. Stop
> instance 2, then run the census.

> ### RI-6 A pending request outlives the guest's call
>
> The RI-1 world lets a guest submit a capability request and continue before
> the decision. The decision reaches the guest later, as an event or through a
> later call. The Runtime records the pending request before the submit call
> returns. Only with this can an instance fail while its own request is pending,
> which A11 needs.
>
> Gap evidence: the only capability call returns the grant itself, so the guest
> waits inside it, and the bridge polls inside that call.

### Quote of the two option titles (read only)

- **Option 1, a non-blocking submit.**
- **Option 2, an instance deadline.**

This task takes neither option into `elastos/`. The stand-in keeps the blocked call shape and stores the request before `finish_start`, so the A11 row here is the lab stand-in only.

### The settlement

`finish_start` finds the instance, refuses an unknown id or a non-live phase, applies the admitted `Start`, stores the result, then returns early unless the phase is `Failed`. A `Failed` result clones that instance's id and stored cause after the mutable borrow ends and calls `settle_pending` once. `settle_pending` changes only that session's `Pending` records to `Denied`, sets `settled_by` to `runtime` and writes the cause. A stop still calls the same function with its `stopped: ` cause.

### Tests

The lib target has three named tests in `standin_runtime::tests`:

- `standin_failed_start_denies_that_sessions_pending` replaces `standin_failed_start_leaves_the_request`. `Start::Error("start refused")` and `Start::Trap("start trapped")` each settle `req-1` as `denied_request("req-1", "component-1", cause)` with that failure cause, and the list entry stays `failed` with the same cause.
- `standin_failed_start_leaves_the_siblings_request` admits `/capsules/fail-after-submit` as `fail-after-submit` with `Start::Error("start refused")` and `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches each path once for `component-1` and `component-2`, both `starting`, and seeds `req-1` and `req-2` before either `finish_start`. The failed start denies `req-1` with `start refused`; `req-2` stays `pending_request("req-2", "component-2")` and `component-2` stays `starting`. The `Ok` start leaves `req-2` pending and `component-2` `running`. The test asserts `standin.grants.is_empty()`. No operator starts and the probe is not built.
- `standin_refused_finish_start_preserves_requests` proves the guards precede settlement: a second start, an unknown id, and a start after a stop all leave the request list unchanged; the failed instance keeps its failure settlement through a refused second start.

`standin_stop_denies_that_sessions_pending` still expects `stopped: stop one`.

### Hand-run falsifiers

No list id. Each plant was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. The planted crate compiled every time. After the last restore, `standin-runtime/mod.rs` matched its post-edit candidate bytes (`sha256 00043bbc31739947b879cfc36b76a8aa21ba6249db8705a14e86e865427b2d40`) and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only. The plant expressions are absent from that file.

F-standin-a11-stub. Named test `standin_failed_start_denies_that_sessions_pending`. Planted exit 101 in 1.36 seconds. Restored exit 0 in 1.59 seconds. Assertion: `src/../standin-runtime/mod.rs:2327:13` `assertion left == right failed: the stand-in denies the failed start's pending request with start refused`. The record stayed `pending` with no settler.

Old:

```text
        if phase != ResidentStatus::Failed {
            return Ok(());
        }
        let session_id = instance.id.clone();
```

New:

```text
        if phase != ResidentStatus::Failed {
            return Ok(());
        }
        if phase == ResidentStatus::Failed {
            return Ok(());
        }
        let session_id = instance.id.clone();
```

F-standin-a11-blank. Named test `standin_failed_start_denies_that_sessions_pending`. Planted exit 101 in 1.73 seconds. Restored exit 0 in 1.72 seconds. Assertion: `src/../standin-runtime/mod.rs:2324:13` `assertion left == right failed: the stand-in denies the failed start's pending request with start refused`. The record had `status` `denied` and `decision_reason` `""`.

Old:

```text
        let cause = instance.cause.clone();
        self.settle_pending(&session_id, &cause);
```

New:

```text
        let cause = instance.cause.clone();
        self.settle_pending(&session_id, "");
```

F-standin-a11-ok-settles. Named test `standin_failed_start_leaves_the_siblings_request`. Planted exit 101 in 0.96 seconds. Restored exit 0 in 1.45 seconds. Assertion: `src/../standin-runtime/mod.rs:2397:9` `assertion left == right failed: the stand-in leaves the sibling's request pending after an Ok start`. The sibling's request was `denied` with `decision_reason` `""`.

Old:

```text
        if phase != ResidentStatus::Failed {
            return Ok(());
        }
        let session_id = instance.id.clone();
        let cause = instance.cause.clone();
        self.settle_pending(&session_id, &cause);
```

New:

```text
        let session_id = instance.id.clone();
        let cause = instance.cause.clone();
        self.settle_pending(&session_id, &cause);
```

F-058-refusal-guard. Named test `standin_refused_finish_start_preserves_requests`. The `settle_pending` call was moved above the `start already returned` guard, so a refused second start settled the running instance's request. Planted exit 101 (2.24 seconds cold, 0.06 seconds warm) at `src/../standin-runtime/mod.rs:2433:9` `assertion left == right failed: the stand-in leaves the request pending after a second start`; the record read `denied` with `settled_by` `runtime`. Restored exit 0 in 1.18 seconds.

Old:

```text
        if instance.phase != ResidentStatus::Starting {
            return Err((400, "start already returned".to_owned()));
        }
```

New:

```text
        if instance.phase != ResidentStatus::Starting {
            let session_id = instance.id.clone();
            let cause = instance.cause.clone();
            self.settle_pending(&session_id, &cause);
            return Err((400, "start already returned".to_owned()));
        }
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.13 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 339.08 seconds, inside the 600-second bound. 176 tests ran: 162 passed, 0 failed, 14 ignored. Lib 48, effects 59 passed with 12 ignored, report 23, runtime 10 with 2 ignored, harness 9, artifact 7, build 1, standin_contract 2, probe 3. No census line and no listed flaky test failed, so the single-rerun rule did not apply.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:358-383` settles one lab instance by its launch id; the change introduces no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:473-481` writes one in-memory request record; it reads no file, network, clock or hardware and imports no `wasi:*`. |
| 3. A second path or a second copy of one rule? | No | `standin-runtime/mod.rs:381` is the one `settle_pending` call from `finish_start`, and `:473` is the one deny rule for `start`, `error`, `trap` and stop. |
| 4. Runtime core grows? | No | The edits are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md:721` and `LOG.md`; `elastos/`, `capsules/` and `scripts/` are unchanged. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:362-378` returns the unknown, non-live and repeated-start reasons before settlement; a `Failed` start denies with that stored failure cause. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The seam settles a request record and mints nothing; the real capability call still returns the grant (`standin-runtime/README.md:29`). |
| 7. Named tests and caught falsifiers prove the rule? | Yes | Tests at `standin-runtime/mod.rs:2311`, `:2340` and `:2419`; the stub, blank-cause and `Ok`-settle plants failed at `:2327`, `:2324` and `:2397`. |
| 8. Identity, admission and allowance stay separate? | Yes | `settle_pending` at `:473-481` reads no grant, no capsule and no budget; `standin_failed_start_leaves_the_siblings_request` asserts the grant list stays empty (`:2414`). |

The real A11 row stays open: the real capability call returns the grant, so RI-6 is a Runtime gap. A PASS here gives the Runtime no A11 credit.

### Stop: the census test's own leftover is outside this task

The supervisor runs failed `cleanup_census_refuses_each_leftover` at `tests/runtime.rs:403` with `cleanup census: FAIL retained:target/home-67644-...-1; process leftover; processes:1 paths:["stdout-25"]` and, on the next run, `retained:target/home-99131-...-0` with the same one-process `stdout-25` shape. The retained `stdout-25` is 646 bytes, the size of an `lsof +D` listing, so the counted file is a collected census-tool capture.

Cause, for the planner and not fixed here: `collect_captures_from` (`src/harness.rs`) renames a completed census tool's captures into the inspected root. The census runs `lsof`, whose forked stat helper inherits the capture file and can outlive the tool; the renamed file then appears under the inspected root, and the next census counts the helper as a process leftover. `src/census.rs:40-41` states that the tool's captures stay outside the inspected roots. A copy instead of a rename keeps the originals in the tool root until it is removed.

`cleanup_census_refuses_each_leftover` is not on the six-test flake list, so Acceptance 6 stops this task on that check. The census change belongs in its own task with its own plan, review and falsifier ids. Tell planner: plan "census tool captures are copied, not moved" with the `stdout-25` evidence.

This branch changes no `src/harness.rs` or `tests/harness.rs` byte. Both files match their `f551d4b0c` blobs: `src/harness.rs` `sha256 39b2093d698636464aeb0d54655b6bee2d4fdeba5e59afe3ef4e90516fb94fc4`, `tests/harness.rs` `sha256 87704b47af39004b27bd445d0a983d0430b15057a83858b914691b4e43fc1801`. No census code, operator fixture, test assertion or dependency changes.

Rerun after the revert:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 262.51 seconds, inside the 600-second bound. 176 tests: 162 passed, 0 failed, 14 ignored. Lib 48, effects 59 passed with 12 ignored, report 23, runtime 10 with 2 ignored, harness 9, artifact 7, build 1, standin_contract 2, probe 3. `cleanup_census_refuses_each_leftover` passed this time; the census race remains open in the planner item above.

## 059 — A12: stopped stand-in leaves no pending request

059: `standin_a12_census` reads the shell live view through `grants::live_grant_state`, reads the shell capsule list, refuses `starting`, `running` and `stopping`, then for each capsule reads that entry's `session_id` and calls the one `get_capability_requests(Shell, Some(session_id))`. A missing session returns `capsule entry requires a session`, a route error returns that reason, a `pending` request returns `pending request leftover`, and any other status including `denied` continues. The physical `census::cleanup` still runs after the loop. `standin_stopped_run_leaves_no_live_grant` seeds `req-p1` and `req-p2` before the two stops, checks that the earlier census still returns `live grant leftover`, checks each stopped session's record is `denied` with `settled_by` `runtime` and the stop cause, and then requires `Ok(())`. A third run with no seed is stopped the same way, seeds `req-left` after the stops, and its census returns `pending request leftover`. No `StandIn` method, no second census function and no second request renderer were added. `standin-runtime/mod.rs`, `src/census.rs`, `tests/common/grants.rs` and `GAPS.md` are byte-identical to the branch base.

The census sentence, read only at `35697329be0aad89eb68d0adf78aa94d24751317:lab/resident-instances/SPEC.md`:

> No pending request comes from a journey session.

This task takes that sentence only. The process-tree walk and `GET /api/health` stay with that harness. A passing row gives the real Runtime no A12 credit, and `run_leaves_no_live_grant` stays `#[ignore = "blocked: AC-021-GRANTS"]`.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects standin_stopped_run_leaves_no_live_grant -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. Each planted crate compiled.

F-standin-a12-skip-pending. Planted exit 101 in 2.53 seconds. Restored exit 0 in 1.88 seconds. Assertion: `tests/effects.rs:1378:5` `the stand-in refuses a pending request after both stops: Ok(())`.

Old:

```text
            if request["status"] == "pending" {
```

New:

```text
            if false && request["status"] == "pending" {
```

F-standin-a12-denied-is-pending. Planted exit 101 in 1.39 seconds. Restored exit 0 in 2.09 seconds. Assertion: `tests/effects.rs:1328:5` `the stand-in leaves no live grant, live instance, pending request or physical leftover after both stops`.

Old:

```text
            if request["status"] == "pending" {
```

New:

```text
            if request["status"] == "pending" || request["status"] == "denied" {
```

The two entries were appended after `F-standin-a12-skip-cleanup`; its `old` and `new` bytes, and those of `F-standin-a12-stub` and `F-standin-a12-skip-status`, are unchanged. Each new `old` occurs once in the formatted file. The three planted-run roots and the first gate's retained root were removed after this record.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.13 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`, first run: exit 101, real 247.99 seconds. The effects target reported 58 passed, 1 failed, 12 ignored in 194.33 seconds. The only failure was `attach_secret_stays_in_memory`, at `tests/effects.rs:497:5`, with `cleanup census: FAIL retained:target/home-36502-1793132017879378000-11; process leftover; processes:1 paths:["stderr-18"] API sockets:0 temp:0 paths:[]`. That is acceptance 6's allowed case: a named test and a process-leftover path matching `stderr-<digits>`.
- Rerun, after no change: exit 0, real 270.46 seconds, inside the 600-second bound. Lib 48, report binary 1, artifact 7, build 1, effects 59 passed with 12 ignored, harness 9, report 23, runtime 10 with 2 ignored, standin_contract 2, probe 3. `standin_stopped_run_leaves_no_live_grant` passed. `run_leaves_no_live_grant` stayed ignored on `AC-021-GRANTS`.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The test reads request records by `session_id` at `tests/effects.rs:1147`; the seeded resource is a Public path, not a code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The change is test code on the lab stand-in; it opens one loopback port and one throwaway home. |
| 3. A second path or a second copy of one rule? | No | `tests/effects.rs:1151` is the one `get_capability_requests` read, inside the one census function; `standin-runtime/mod.rs` keeps the one settlement rule. |
| 4. Runtime core grows? | No | No `elastos/`, `capsules/` or `scripts/` edit. |
| 5. Refusals deny by default with a clear reason? | Yes | `tests/effects.rs:1149`, `:1152` and `:1158` return `capsule entry requires a session`, the route reason, and `pending request leftover`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The test seeds the stand-in and adds no capsule import; the real capability call still returns the grant. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `tests/effects.rs:1170` `standin_stopped_run_leaves_no_live_grant`; the two plants above fail it and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | `tests/effects.rs:1129` reads the grant view, `:1144` the instance list and `:1151` the request store as separate reads; the stop at `:1266` settles only that session's requests. |

## 060 — A6: a shell deny fails the waiting sibling

060: `StandIn` gains `post_capability_deny` at `standin-runtime/mod.rs:304`, the answer for `POST /api/capability/deny`. It calls `require_shell` at `:309` before the body is read, parses the body once in `deny_body` at `:797`, refuses an unknown id at `:316` or a non-pending record at `:319`, and calls the one writer `deny_record` at `:322` with `shell`. `deny_record` at `:517` now holds the three settlement writes; `settle_pending` at `:533` collects one session's pending ids and calls that same writer with `runtime`, so `stop_one` at `:500` and the failed-start arm at `:424` keep their behaviour and there is no second writer. When the denied request's session has an instance whose phase is `Starting` at `:329`, the route stores `failed`, the deny reason as `cause` and `ended_at` from the test instant; any other phase stays. `authorise`, `seed_grant`, `finish_start`, `stop_one`, `revoke_live`, `keep`, `visible`, `storage_for_home` and `confirm_storage` are unchanged. Two tests sit in the module's `#[cfg(test)]`: `standin_shell_deny_fails_the_waiting_sibling` at `:2632` and `standin_shell_deny_refuses_a_bad_request` at `:2781`.

### Quote from the resident SPEC (read only at `35697329be0aad89eb68d0adf78aa94d24751317`)

```text
**A6.** Launch `read-shared` twice. Grant instance 1 only, and wait until it
is `running`. The live-grant view shows exactly one grant, bound to instance 1.
Instance 2's request for the same resource is still pending, in its own
session. Deny it. Instance 2 ends `failed` with the denial in its cause, and
instance 1 is still `running` with the same single grant. Stop instance 1. The
census also requires zero live grants for both sessions.
```

This task takes the deny sentence only: instance 2's request stays pending while instance 1's grant is live, the deny ends instance 2 `failed` with the denial in its cause, and instance 1 stays `running` with that grant. The census sentence stays 049 and 059.

### Quote of the two route facts (read only)

`elastos/crates/elastos-server/src/api/handlers/capability.rs:366-371`:

```rust
pub struct DenyRequestInput {
    /// Request ID to deny
    pub request_id: String,
    /// Reason for denial (optional)
    pub reason: Option<String>,
}
```

`:388` gives the missing reason, and `:403-406` gives the Ok body:

```rust
    let reason = input.reason.unwrap_or_else(|| "Denied by user".to_string());
```

```rust
    Ok(Json(DenyRequestOutput {
        success: true,
        error: None,
    }))
```

`elastos/crates/elastos-runtime/src/capability/pending.rs:393-395` applies a denial only to a pending request:

```rust
        if !matches!(request.status, RequestStatus::Pending) {
            return Err(format!("Request {} is not pending", request_id));
        }
```

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. Each planted crate compiled. Each named test failed on its assertion and passed again after the restore.

F-standin-a6-deny-stub. Planted exit 101 in 2.30 seconds. Restored exit 0 in 0.07 seconds. Assertion: `standin-runtime/mod.rs:2687:9` `the stand-in denies the named request with the shell as settler and leaves req-extra pending`.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (request_id, reason) = deny_body(body)?;
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "success": true }));
        require_shell(caller)?;
        let (request_id, reason) = deny_body(body)?;
```

F-standin-a6-deny-runtime. Planted exit 101 in 2.31 seconds. Restored exit 0 in 1.14 seconds. Assertion: `standin-runtime/mod.rs:2686:9` `the stand-in denies the named request with the shell as settler and leaves req-extra pending`.

Old:

```text
        self.deny_record(request_id, reason, "shell");
```

New:

```text
        self.deny_record(request_id, reason, "runtime");
```

F-standin-a6-deny-stays-starting. Planted exit 101 in 1.97 seconds. Restored exit 0 in 0.79 seconds. Assertion: `standin-runtime/mod.rs:1346:9` in `assert_capsule` `the stand-in ends the waiting instance failed with the deny reason`.

Old:

```text
        let session_id = request.session_id.clone();
        self.deny_record(request_id, reason, "shell");
        let instant = self.instant;
        if let Some(instance) = self
            .instances
            .iter_mut()
            .find(|instance| instance.id == session_id.as_str())
        {
            if instance.phase == ResidentStatus::Starting {
                instance.phase = ResidentStatus::Failed;
                instance.cause = reason.to_owned();
                instance.ended_at = Some(instant);
            }
        }
        Ok(json!({ "success": true }))
```

New:

```text
        let session_id = request.session_id.clone();
        self.deny_record(request_id, reason, "shell");
        let _ = session_id;
        Ok(json!({ "success": true }))
```

After the restores, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` added lines contain only `self.deny_record(request_id, reason, "shell");` among the three plant markers, so no plant remains. No `falsifiers.json` id was added.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.12 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`, first run: real 270.82 seconds, inside the 600-second bound. Cargo ran every target through the doc-tests and printed no `error: test failed` line.
- Recorded run: exit 0, real 276.79 seconds. 50 lib tests, 1 report binary, 7 artifact, 1 build, 59 effects passed with 12 ignored, 9 harness, 23 report, 10 runtime with 2 ignored, 2 standin_contract, 3 probe. Both new deny tests passed. The earlier 059 ignores stay: `run_leaves_no_live_grant` on `AC-021-GRANTS`, `parallel_capsules_complete_independently` on `RT4`, and `instance_grant_does_not_authorise_sibling`.
- One intermediate run failed on a process leftover: exit 101, real 267.12 seconds. The only failure was `undeclared_network_manifest_is_refused`, at `tests/effects.rs:82:14`, with `cleanup census: FAIL retained:target/home-30204-1793134595005459000-231; process leftover; processes:1 paths:["stdout-237"] API sockets:0 temp:0 paths:[]`. That row and the census are untouched by this task; the leftover path is `stdout-<digits>`, with no `host-process.lock` and no `config.toml` path. The following identical run passed as recorded above.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `standin-runtime/mod.rs:1370` keeps the seeded Public resource path; the route identifies the request by its stored `request_id` at `:314`, and no code or content identity is added. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:309` refuses every client with `This endpoint requires shell privileges`; the route is a lab stand-in method and `seed_grant` at `:212` is unchanged, so no grant is created or widened. |
| 3. A second path or a second copy of one rule? | No | One body parser at `:797`, one settlement writer at `:517`; `settle_pending` at `:533` and the deny route at `:322` both call it, and `get_capability_requests` at `:279` stays the one read. |
| 4. Runtime core grows? | No | No `elastos/`, `capsules/` or `scripts/` edit; the diff touches only `lab/agent-conformance/`. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:309` gives 403; `:316`, `:319` and `deny_body` at `:797-829` give 400 with a reason that names the refused id, status or key. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The change adds no capsule code or import; `authorise` at `:357` still refuses the sibling with `wrong capsule` at `:2740`. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:2632` and `:2781`; the three plants above fail their named test and the restored tests pass. |
| 8. Identity, admission and allowance stay separate? | Yes | The deny writes only the request record at `:517` and the instance phase at `:329`; `seed_grant` at `:212` is untouched, so the live set stays exactly `req-g` at `:2721`, and the sibling still fails presentation at `:2740`. |

## 061 — A6: shell grant turns a pending request live

061: `StandIn` gains `post_capability_grant` at `standin-runtime/mod.rs:348`, the answer for `POST /api/capability/grant`. It calls `require_shell` at `:353` before the body is read, parses the body once in `grant_body` at `:890`, refuses an unknown id at `:361` or a non-pending record at `:365`, calls the one writer `settle_record` at `:565` with `granted` and `shell` at `:369`, and calls the unchanged `seed_grant` at `:371` for one `Live` grant. `settle_record` now takes the status as its second argument; the deny route at `:326` and `settle_pending` at `:597` still pass `denied`, so `stop_one` and the failed-start arm keep their behaviour and there is no second writer. The route changes no instance phase or cause and returns only `{"success": true}`. Two named lib tests, three hand-run plants, no new `falsifiers.json` id. `GAPS.md`, `falsify.py`, `src/census.rs`, `tests/effects.rs`, `src/harness.rs`, `Cargo.toml` and `Cargo.lock` are unchanged.

### Quote from the resident SPEC (read only at `35697329be0aad89eb68d0adf78aa94d24751317`)

The grant sentences this task takes:

```text
Grant instance 1 only, and wait until it is `running`. The live-grant view shows
exactly one grant, bound to instance 1. Instance 2's request for the same
resource is still pending, in its own session.
```

The deny sentence stays 060, and the census sentence stays 049 and 059.

### Quote of the route facts (read only)

`elastos/crates/elastos-server/src/api/handlers/capability.rs:270-279`:

```rust
pub struct GrantRequestInput {
    /// Request ID to grant
    pub request_id: String,
    /// Duration: "once" or "session"
    #[serde(default = "default_duration")]
    pub duration: String,
    /// Shell's rationale for granting (passed to PolicyEvaluator audit)
    #[serde(default)]
    pub rationale: Option<String>,
}
```

`:281-283` gives the missing-duration default, and `:328` gives the missing-rationale default:

```rust
fn default_duration() -> String {
    "session".to_string()
}
```

```rust
    let rationale = input.rationale.as_deref().unwrap_or("Shell auto-grant");
```

`elastos/crates/elastos-runtime/src/capability/pending.rs:84-92` accepts `once` and `session`, ignoring case, and refuses any other word with the given text:

```rust
        match s.to_lowercase().as_str() {
            "once" => Ok(GrantDuration::Once),
            "session" => Ok(GrantDuration::Session),
            _ => Err(format!(
                "Invalid duration: {}. Expected 'once' or 'session'",
                s
            )),
        }
```

`pending.rs:368-370` changes only a pending request, and `capability.rs:303-306` parses the duration before it reads the request.

The five functions re-found after 060 and left as found, apart from the writer's added status argument: `post_capability_deny` at `:308`, `seed_request` at `:242`, `get_capability_requests` at `:283`, `seed_grant` at `:216` and `authorise` at `:403`. `finish_start` keeps its one `settle_pending` call on the `Failed` arm, and `stop_one` keeps its call after `revoke_live`. `authorise` and `seed_grant`'s body are unchanged. Grepping `request.status =`, `request.decision_reason =` and `request.settled_by =` finds only `settle_record` at `:577-579`, so the one writer remains the only function that sets those three fields.

### The route

`post_capability_grant` answers `POST /api/capability/grant`. `require_shell` runs before the body is read; a client is status 403 with `This endpoint requires shell privileges`. `grant_body` accepts only `request_id`, `duration` and `rationale`. A missing `request_id`, or a body that is not an object, is `grant body needs request_id`; a non-string field is `grant request_id must be a string`, `grant duration must be a string` or `grant rationale must be a string`; any other key is `grant body rejects ` plus that key. A missing duration is `session`, and a lowercased `once` or `session` is stored as that lowercase word. Any other duration is `Invalid duration: ` plus the given text plus `. Expected 'once' or 'session'`. A missing rationale is `Shell auto-grant`; a present string, including empty, is stored as given. An unknown id is `unknown request: ` plus it; a non-pending record is `request is not pending: ` plus it. Each refusal returns before the writer and before `seed_grant`, so no record, grant or instance changes. On success the one writer stores `granted`, the rationale and `shell`; `seed_grant` stores the same `request_id` and `session_id`, the record's `resource` and `action`, the canonical duration, `granted_at` from the test instant, `Life::Live` and `session_ended` false. The Ok body has no token. No instance phase or cause changes.

### Tests

Two named tests in `standin_runtime::tests`:

- `standin_shell_grant_makes_one_live_grant` at `:3074` admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice as `component-1` and `component-2` (both `starting`), seeds `req-1` and `req-2`, sets instant 4, and grants `req-1` with `duration: "Session"` and rationale `grant shared read`. The shell record for `component-1` is the `granted_request` tuple; `component-2`'s `req-2` stays pending with a null settler. The live set is exactly `req-1`, with `session_id` `component-1`, `resource` the seeded Public path, `action` `read`, `duration` `session` and `granted_at` 4. The client list for `component-2` is empty. `authorise` accepts the `component-1` client for `req-1` and refuses the `component-2` client with `wrong capsule`. Both entries stay `starting` with cause `""`. After `finish_start("component-1")` it is `running` with cause `""`, the record and the one live grant stay, and the sibling stays `starting` with `req-2` pending.
- `standin_shell_grant_refuses_a_bad_request` at `:3239` covers the client 403, `{}` and a non-object for `grant body needs request_id`, non-string `request_id`, `duration` and `rationale`, an unknown id, an extra `token` key, `duration: "minutes"`, and asserts every refusal leaves the pending record, no grant and the `starting` instance. A grant with only `request_id` stores `Shell auto-grant` and the `session` duration. A second grant is `request is not pending:`. A later grant of a stopped instance's `req-s` is `request is not pending:`, its record stays `denied` with `settled_by` `runtime` and cause `stopped: stop one`, and the live view has no `req-s`.

No operator starts and no probe is built.

### Hand-run falsifiers

No list id. Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_grant_makes_one_live_grant -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. Each planted crate compiled. After the last restore the file matched its pre-plant bytes (`sha256 8748c69a308f7451a1c6e786264d57b9dd310ad2d0ed8b63d7edfb7e98c3ce7f`) and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed no plant expression.

F-standin-a6-grant-stub. Planted exit 101 in 1.89 seconds. Restored exit 0 in 0.13 seconds. Assertion: `standin-runtime/mod.rs:3121:9` `assertion left == right failed: the stand-in grants req-1 with the shell as settler and the rationale as decision`; the record stayed `pending` with a null settler.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "success": true }));
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

F-standin-a6-grant-no-live. Planted exit 101 in 1.06 seconds. Restored exit 0 in 0.13 seconds. Assertion: `standin-runtime/mod.rs:3126:9` `assertion left == right failed: the stand-in shows exactly the granted request as live`; the live set was empty.

Old:

```text
        self.settle_record(&request_id, RequestStatus::Granted, rationale, "shell");
        let instant = self.instant;
        self.seed_grant(
            &request_id,
            &session_id,
            &resource,
            &action,
            duration,
            instant,
            Life::Live,
            false,
        );
        Ok(json!({ "success": true }))
```

New:

```text
        self.settle_record(&request_id, RequestStatus::Granted, rationale, "shell");
        Ok(json!({ "success": true }))
```

F-standin-a6-grant-sibling. Planted exit 101 in 1.05 seconds. Restored exit 0 in 0.13 seconds. Assertion: `standin-runtime/mod.rs:3151:9` `assertion left == right failed: the stand-in leaves the sibling request pending with no settler`; `req-2` was `granted` with `settled_by` `shell`.

Old:

```text
            Life::Live,
            false,
        );
        Ok(json!({ "success": true }))
```

New:

```text
            Life::Live,
            false,
        );
        let siblings = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .map(|request| {
                (
                    request.request_id.clone(),
                    request.session_id.clone(),
                    request.resource.clone(),
                    request.action.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (sibling_id, sibling_session, sibling_resource, sibling_action) in siblings {
            self.settle_record(&sibling_id, RequestStatus::Granted, rationale, "shell");
            self.seed_grant(
                &sibling_id,
                &sibling_session,
                &sibling_resource,
                &sibling_action,
                duration,
                instant,
                Life::Live,
                false,
            );
        }
        Ok(json!({ "success": true }))
```

### Docs

`standin-runtime/README.md:45` adds the grant route before `## Callers`: the route, its three body keys and refusals, the one writer storing `status` `granted` and `settled_by` `shell`, `seed_grant` storing the one `Live` grant the RA-1 view shows, the token-free Ok body, a `once` grant staying in that view until a stop revokes it, `authorise` as the presentation check, and the unchanged deny using `settled_by` `shell` with `status` `denied`. It says this value is the lab stand-in and the real route can replace it later because the JSON matches (M1-R), and a PASS gives the Runtime no A6 credit for this grant. The RA-1 section and the existing request sections stay. `RUNBOOK.md` gains one paragraph after the last stand-in paragraph naming `standin_shell_grant_makes_one_live_grant` and the absence of A6 credit; every other paragraph is unchanged.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.15 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 252.36 seconds, inside the 600-second bound. Lib 52; report binary 1; artifact 7; build 1; effects 59 passed with 12 ignored; harness 9; report 23; runtime 10 passed with 2 ignored; standin_contract 2; probe 3. That is 167 passed, 0 failed and 14 ignored. Both new grant tests passed. The earlier ignores stay: `run_leaves_no_live_grant` on `AC-021-GRANTS`, `parallel_capsules_complete_independently` on `RT4`, and `instance_grant_does_not_authorise_sibling`. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the restores: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.15 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_grant_makes_one_live_grant -- --exact` exit 0, real 0.13 seconds, 1 passed.
- `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `Cargo.toml` and `Cargo.lock` is empty. Only `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md` change.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The route identifies the request and grant by its stored `request_id` at `:361`; `seed_grant` stores the seeded Public resource path at `:371`; no code or content identity is added. |
| 2. Capsule, Home or UI gains ungranted access? | No | `standin-runtime/mod.rs:353` refuses every client with `This endpoint requires shell privileges`; the route reads no file, network, clock or hardware and imports no `wasi:*`. |
| 3. A second path or a second copy of one rule? | No | One body parser `grant_body` at `:890`, one writer `settle_record` at `:565`; `get_capability_requests` at `:283` and `get_capability_list` at `:384` stay the reads, and `seed_grant` at `:216` stays the one grant store call. |
| 4. Runtime core grows? | No | No `elastos/`, `capsules/` or `scripts/` edit; the diff touches only `lab/agent-conformance/`. |
| 5. Refusals deny by default with a clear reason? | Yes | `standin-runtime/mod.rs:353` gives 403; `:361`, `:365` and `grant_body` at `:890-945` give 400 with a reason that names the refused id, status or key. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The change is a lab route with no capsule code or import; the real capability call still returns the grant and the stand-in only records the permitted effect. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:3074` and `:3239`; the stub, no-live and sibling plants fail the named test at `:3121`, `:3126` and `:3151`, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The grant writes one request record and one grant at `:369-380`; it changes no instance phase, so `finish_start` remains the admission decision and `duration` stays an allowance value; `authorise` at `:403` stays the presentation check. |

The real A6 row stays open: the real route returns a token and the Runtime still owns the admission decision. A PASS here gives the Runtime no A6 credit for this grant.

## 062 — A10/A11: an ended instance makes no request and stays listed

062: `StandIn` gains one lab observation, `watch_ended(session_id, ended) -> Result<(), (u16, String)>`. Its doc comment starts `Lab observation, not a route.` It takes `&self`, reads no clock and no disk, and calls the existing `get_capsules(Caller::Shell)` and `get_capability_requests(Caller::Shell, Some(session_id))`. It walks neither `instances` nor `requests`, adds no renderer, and calls no writer. The checks run in this order, each refusal status 400: an `ended` other than `stopped` or `failed` is `watch status must be stopped or failed` before either read; a missing list entry is `left the instance list: ` plus the id; a listed status other than `ended` is `changed from ` plus `ended` plus ` to ` plus the actual status plus `: ` plus the id; a `pending` record is `made a request after it ended: ` plus the id; a request count other than 1 is the id plus ` has ` plus the decimal count plus ` request records after it ended`. `Ok(())` and every refusal leave instances, requests and grants as they were. `seed_request`, `settle_pending`, `stop_one`, `finish_start`, `keeps_instance`, `get_capsules` and `get_capability_requests` are unchanged. No `falsifiers.json` id was added.

### Quote from the resident SPEC (read only)

> All bounds below are the harness's: 10 seconds for every awaited transition,
> a 2-second watch after an instance ends, and a 1-second dwell for residency.

> For the watch, instance 1 makes no request and stays
> `stopped`. Stop instance 2, then run the census.

> For the watch, instance 1 makes no request and stays `failed`. Stop
> instance 2, then run the census.

### Tests

Two tests in `standin_runtime::tests`, each passing with no operator and no probe build. Both use the existing `denied_request`, `pending_request`, `request_entries`, `assert_capsule` and `assert_request_refused` helpers.

- `standin_stopped_instance_makes_no_request` (`:3809`) admits `/capsules/read-shared`, launches twice and finishes both starts, so `component-1` and `component-2` are `running`. It seeds `req-1` on `component-1` and `req-2` on `component-2`, stops `component-1` with `{"reason":"stop one"}` at instant 0, sets instant 2, and `watch_ended("component-1", "stopped")` is `Ok(())`. The list keeps `component-1` `stopped` with cause `stopped: stop one` and `component-2` `running`; the shell record for `component-1` is `denied_request("req-1", "component-1", "stopped: stop one")` and for `component-2` is `pending_request("req-2", "component-2")`. `seed_request("req-retry", "component-1", ...)` then `watch_ended` is 400 with `made a request after it ended: component-1`; `req-1` stays denied, `req-retry` stays pending and the entry stays `stopped`. `watch_ended("component-1", "running")` is `watch status must be stopped or failed` and changes no record, and `watch_ended("component-9", "stopped")` is `left the instance list: component-9`. A second `StandIn` stops `component-1` at instant 0 with one seeded request: the watch is `Ok(())` at instant 2 and 400 with `left the instance list: component-1` at instant 60, and the record is still the one denied request.
- `standin_failed_instance_makes_no_request` (`:3945`) admits `/capsules/fail-after-submit` as `fail-after-submit` with `Start::Error("start refused")` and `/capsules/read-shared` with `Start::Ok`, launches both (`component-1` and `component-2`, both `starting`), seeds `req-1` and `req-2` before `finish_start`, finishes `component-1` at instant 0 and sets instant 2. `watch_ended("component-1", "failed")` is `Ok(())`; the list keeps `component-1` `failed` with cause `start refused` and `component-2` `starting`; `req-1` is `denied_request("req-1", "component-1", "start refused")` and `req-2` stays pending. A third `StandIn` admits only the failing path, launches once and finishes the start with no seeded request: at instant 2 the watch is 400 with `component-1 has 0 request records after it ended`, the entry stays `failed` with cause `start refused`, `grants` is empty and no sibling stops.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `env RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact`. The planted crate compiled every time, and every planted run exited 101. After the last restore, `sha256sum standin-runtime/mod.rs` was `03ec278bad100bf68039f38c821f487a453112c9638a4ff9090853e477bf4e53`, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only, and no plant expression remained.

F-standin-watch-stub. Named test `standin_stopped_instance_makes_no_request`. Planted exit 101 in 1.53 seconds; restored it passes in the proof run. Assertion: `src/../standin-runtime/mod.rs:1625:9` `the stand-in watch reports the pending request that appeared after the end: Ok(())`.

Old:

```text
    pub fn watch_ended(&self, session_id: &str, ended: &str) -> Result<(), (u16, String)> {
        if ended != "stopped" && ended != "failed" {
```

New:

```text
    pub fn watch_ended(&self, session_id: &str, ended: &str) -> Result<(), (u16, String)> {
        return Ok(());
        if ended != "stopped" && ended != "failed" {
```

F-standin-watch-ignore-pending. Named test `standin_stopped_instance_makes_no_request`. Planted exit 101 in 0.98 seconds; restored it passes in the proof run. Assertion: `src/../standin-runtime/mod.rs:1618:9` `the stand-in watch reports the pending request that appeared after the end: Err((400, "component-1 has 2 request records after it ended"))`.

Old:

```text
            .unwrap_or(&[]);
        if requests
            .iter()
            .any(|request| request["status"] == "pending")
        {
            return Err((400, format!("made a request after it ended: {session_id}")));
        }
        if requests.len() != 1 {
```

New:

```text
            .unwrap_or(&[]);
        if requests.len() != 1 {
```

F-standin-watch-ignore-list. Named test `standin_stopped_instance_makes_no_request`. Planted exit 101 in 1.69 seconds; restored it passes in the proof run. Assertion: `src/../standin-runtime/mod.rs:1623:9` `the stand-in watch reports an instance that is not listed: Err((400, "component-9 has 0 request records after it ended"))`.

Old:

```text
        let Some(entry) = listed["capsules"]
            .as_array()
            .and_then(|capsules| capsules.iter().find(|entry| entry["id"] == session_id))
        else {
            return Err((400, format!("left the instance list: {session_id}")));
        };
        let status = entry["status"].as_str().unwrap_or("");
        if status != ended {
```

New:

```text
        let entry = listed["capsules"]
            .as_array()
            .and_then(|capsules| capsules.iter().find(|entry| entry["id"] == session_id));
        let status = entry
            .map(|entry| entry["status"].as_str().unwrap_or(""))
            .unwrap_or("");
        if entry.is_some() && status != ended {
```

F-standin-watch-ignore-count. Named test `standin_failed_instance_makes_no_request`. Planted exit 101 in 1.24 seconds; restored it passes in the proof run. Assertion: `src/../standin-runtime/mod.rs:1615:9` `the stand-in watch counts the failed instance's request records: Ok(())`.

Old:

```text
        if requests.len() != 1 {
            return Err((
                400,
                format!(
                    "{session_id} has {} request records after it ended",
                    requests.len()
                ),
            ));
        }
        Ok(())
```

New:

```text
        Ok(())
```

### Docs

`standin-runtime/README.md:47` adds one paragraph immediately before `## Callers`: `watch_ended` is a lab observation, not a route; it calls `get_capsules` and `get_capability_requests`; two seconds after a stop the instance is still listed `stopped` with one request that is not pending, and two seconds after a failed start the same holds for `failed`; a pending request on that session is `made a request after it ended`; at 60 seconds the instance has left the list; `seed_request` can still store a pending record after the end, and the watch reports it and does not remove it; a PASS gives the Runtime no A10 or A11 credit for this watch. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph, the census sentence and `## Callers` stay. `RUNBOOK.md:729` adds one paragraph after the last stand-in paragraph naming both tests and the no-credit limit.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/standin_contract.rs`, `tests/common/grants.rs`, `GAPS.md`, `Cargo.toml` and `Cargo.lock` is empty.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 261.12 seconds, inside the 600-second bound. The lib target holds 54 tests, including both new ones (57 across lib and probe by `-- --list`). The observed tail: report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the restores: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.16 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib instance_makes_no_request` exit 0, real 0.11 seconds, 2 passed and 0 failed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The observation reads the stored `session_id` at `standin-runtime/mod.rs:308`; it adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | `watch_ended` takes `&self` at `:308` and reads no file, network, clock or hardware; it grants nothing and mints no token. |
| 3. A second path or a second copy of one rule? | No | It calls `get_capsules` at `:312` and `get_capability_requests` at `:326`; it walks no store, adds no renderer and calls no writer. |
| 4. Runtime core grows? | No | The diff touches only `lab/agent-conformance/`; `elastos/`, `capsules/` and `scripts/` are untouched. |
| 5. Refusals deny by default with a clear reason? | Yes | Each check returns status 400 with the named reason at `:309`, `:317`, `:320`, `:335` and `:337`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | This is a lab observation with no capsule code; it reads the shell view that the real route already answers. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin-runtime/mod.rs:3809` and `:3945`; the stub, ignore-pending, ignore-list and ignore-count plants each fail the named test, and the restored tests pass. |
| 8. Identity, admission and allowance stay separate? | Yes | The watch reads the instance list and request records at `:312-330`; it changes no phase, request or grant, so `finish_start` stays the admission decision and no allowance is minted. |

A passing row gives the real Runtime no A10 or A11 credit for this watch.

## 063 — A10/A11: survivor runs after the other ends

063: `tests/effects.rs` gains `standin_cancel_survivor_reaches_running` and `standin_failed_survivor_reaches_running`; both use the one grant route, the one start return and the one census, and the stand-in sources stay as found. `standin-runtime/README.md` gains the survivor paragraph before `## Callers`, and `RUNBOOK.md` gains one paragraph after the last stand-in paragraph. `GAPS.md`, `falsifiers.json`, `Cargo.toml`, `Cargo.lock`, `src/census.rs`, `src/harness.rs`, `tests/common/grants.rs` and `standin-runtime/mod.rs` are unchanged.

### Quote from the resident SPEC (read only at `35697329be0aad89eb68d0adf78aa94d24751317`)

The grant sentences this task takes:

```text
Instance 2 is still live and its request is still pending. Grant it; instance
2 reaches `running`. For the watch, instance 1 makes no request and stays
`stopped`. Stop instance 2, then run the census.
```

```text
Grant instance 2; it reaches `running`. For the watch, instance 1 makes no
request and stays `failed`. Stop instance 2, then run the census.
```

The watch sentences stay 062.

### Tests

Both tests live in `tests/effects.rs`, pass with no operator and no probe build, and bind one `127.0.0.1:0` port, drop the listener and pass that port to the one census as `standin_stopped_run_leaves_no_live_grant` does. They share local assertion helpers at `:1392` (`standin_launch`), `:1402` (`standin_capsule`), `:1435` (`standin_request_record`), `:1454` (`standin_live_grants`) and the resource constant `localhost://Public/resident-instances/shared.txt`. Every assertion message starts `the stand-in`.

- `standin_cancel_survivor_reaches_running` (`:1476`) admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice without `finish_start` (`component-1` and `component-2`, both `starting`), seeds `req-1` and `req-2`, and deletes `component-1` with `{"reason":"stop one"}`. `component-1` is `stopped` with cause `stopped: stop one`; its record is `req-1` `denied`, `settled_by` `runtime`, `decision_reason` `stopped: stop one`. `component-2` stays `starting` with cause `""`, and `req-2` stays `pending` with `settled_by` null. At instant 4 the shell grant of `req-2` with duration `session` and rationale `grant shared read` is Ok `{"success": true}`; `component-2` stays `starting`, its record is `req-2` `granted` with `settled_by` `shell` and that rationale, the ended record stays unchanged, and the live-grant view is exactly one `req-2` entry with `session_id` `component-2`, `duration` `session` and `granted_at` 4. `authorise` accepts the `component-2` client and refuses the `component-1` client with 403 and `wrong capsule`. `finish_start("component-2")` stores `running` with cause `""`, keeps the granted record and the one live grant, and the census is `Err` containing `live grant leftover`. The stop with `{"reason":"stop two"}` stores `stopped` with cause `stopped: stop two`, keeps `req-2` granted with `settled_by` `shell`, empties the live view, refuses the stopped survivor's presentation with 400 and a reason that starts `grant is not live:` and contains `Revoked`, and the census is `Ok(())`. `home.finish()` is Ok.
- `standin_failed_survivor_reaches_running` (`:1734`) admits `/capsules/fail-after-submit` with `Start::Error("start refused")` and `/capsules/read-shared` with `Start::Ok`, launches the failing path then the shared path (both `starting`), and seeds `req-1` and `req-2` before `finish_start`. `finish_start("component-1")` stores `failed` with cause `start refused` and denies `req-1` with `settled_by` `runtime` and that cause; `component-2` stays `starting` and `req-2` pending. At instant 4 the same shell grant of `req-2` is Ok `{"success": true}`; the failed instance and its denied record stay, `component-2` stays `starting`, and the live view is exactly `req-2` on `component-2`. `finish_start("component-2")` stores `running` with cause `""`, the census is `Err` containing `live grant leftover`, the stop with `{"reason":"stop two"}` makes the census `Ok(())`, and the failed instance's denied record stays. `home.finish()` is Ok.

No new `StandIn` method. The tests call `post_capability_grant`, `finish_start`, `delete_capsule` and `standin_a12_census`; they call neither `seed_grant` nor `settle_pending`, and `watch_ended` stays uncalled.

### Hand-run falsifiers

No `falsifiers.json` id. Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects standin_cancel_survivor_reaches_running -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. Each planted crate compiled. After the last restore `sha256sum standin-runtime/mod.rs` was `03ec278bad100bf68039f38c821f487a453112c9638a4ff9090853e477bf4e53`, which matches the value 062 recorded, and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` was empty.

F-standin-survivor-session: the session id passed to `seed_grant` is the literal `component-1`. Planted run failed on the assertion at `tests/effects.rs:1615:5`: `the stand-in stores the one live grant for the survivor's session at the test instant`; the live entry's `session_id` was `component-1` and the expected value was `component-2`. Planted real 2.40 seconds. Restored real 2.03 seconds, 1 passed.

Old:

```text
        self.seed_grant(
            &request_id,
            &session_id,
```

New:

```text
        self.seed_grant(
            &request_id,
            "component-1",
```

F-standin-survivor-ended: on the success path the one writer is also called for every denied record, with `granted` and `shell` and the same rationale. Planted run failed on the assertion at `tests/effects.rs:1590:5`: `the stand-in leaves the ended instance's denied record unchanged`; `req-1` became `granted` with `settled_by` `shell` and `decision_reason` `grant shared read`. Planted real 1.69 seconds.

Old:

```text
        self.seed_grant(
            &request_id,
            &session_id,
            &resource,
            &action,
            duration,
            instant,
            Life::Live,
            false,
        );
        Ok(json!({ "success": true }))
```

New:

```text
        self.seed_grant(
            &request_id,
            &session_id,
            &resource,
            &action,
            duration,
            instant,
            Life::Live,
            false,
        );
        let ended_denials = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Denied)
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for denied_id in ended_denials {
            self.settle_record(&denied_id, RequestStatus::Granted, rationale, "shell");
        }
        Ok(json!({ "success": true }))
```

### Docs

`standin-runtime/README.md:49` adds the survivor paragraph immediately before `## Callers`: after one instance has ended, `post_capability_grant` of the survivor's pending request stores one `Live` grant for the survivor's session, `finish_start` then stores `running`, the ended request stays `denied` with `settled_by` `runtime`, stopping the survivor makes `standin_a12_census` return success, and the grant does not change phase. It says a PASS gives the Runtime no A10 or A11 credit for the survivor. The RA-1 section, the RI-1 to RI-4 section, the 061 grant paragraph and the 062 watch paragraph stay. `RUNBOOK.md:731` adds one paragraph after the last stand-in paragraph naming both tests and the same no-credit statement. No other RUNBOOK paragraph changes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. `Cargo.toml` and `Cargo.lock` are unchanged, and the protected diff is empty: `git diff` for `standin-runtime/mod.rs`, `src/census.rs`, `src/harness.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `tests/effects.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 248.29 seconds, inside the 600-second bound. The command ran every target and reported no failure. The observed tail was report 23 passed, runtime 10 passed with 2 ignored, standin_contract 2 passed, probe 3 passed and doc-tests 0; it carried no `error: test failed` line. Cargo stops after a failing target, so the targets before those in the sequence passed.
- The effects target alone, recorded for its complete result: exit 0, real 208.15 seconds, 61 passed, 0 failed and 12 ignored. Both new survivor tests passed. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test effects survivor_reaches_running` exit 0, real 0.40 seconds, 2 passed and 0 failed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The tests use the seeded Public resource path at `tests/effects.rs:1390` and stored request ids only. No code or content identity is added. |
| 2. Capsule, Home or UI gains ungranted access? | No | The one grant route refuses every client with `This endpoint requires shell privileges` before the body is read; `standin-runtime/mod.rs:400`. The tests launch and stop through shell calls only. |
| 3. A second path or a second copy of one rule? | No | The tests call `post_capability_grant` at `tests/effects.rs:1560`, `finish_start` at `:1647`, `delete_capsule` at `:1684` and `standin_a12_census` at `:1677`; `seed_grant` at `standin-runtime/mod.rs:418` stays the one grant store and `settle_record` at `:612` stays the one writer. No new method. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/`, `capsules/` and `scripts/` are untouched. |
| 5. Refusals deny by default with a clear reason? | Yes | The tests assert the 403 `wrong capsule` refusal at `tests/effects.rs:1642` and the 400 `grant is not live:` with `Revoked` at `:1722`; both come from the unchanged `authorise` at `standin-runtime/mod.rs:450`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The change adds tests and documentation only; no capsule code or import changes, and the stand-in keeps the one shell view the real route answers. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_cancel_survivor_reaches_running` at `tests/effects.rs:1476` and `standin_failed_survivor_reaches_running` at `:1734`; the session and ended-denial plants fail those named tests on their assertions, and the restored tests pass. |
| 8. Identity, admission and allowance stay separate? | Yes | The unchanged grant route writes one request record and one `Live` grant and changes no phase at `standin-runtime/mod.rs:416-429`; `finish_start` at `:494` stays the admission decision, and `duration` stays the allowance value. A PASS gives the Runtime no A10 or A11 credit for the survivor. |

## 064 — A10/A11: an unanswered request expires

064: `standin-runtime/mod.rs` gains `REQUEST_TIMEOUT_SECS` (300), `RequestStatus::Expired`, the `requested_at` field on `Request`, the private `expire_due`, the `set_instant` call to it, the `expired_request` helper and `standin_unanswered_request_expires`; `set_instant` stores the instant then expires the due pending requests through the one writer. `standin-runtime/README.md` gains the expiry paragraph before `## Callers`, and `RUNBOOK.md` gains one paragraph after the last stand-in paragraph. `elastos/`, `capsules/`, `scripts/`, `examples/`, `GAPS.md`, `falsifiers.json`, `Cargo.toml`, `Cargo.lock`, `src/harness.rs`, `src/census.rs`, `tests/effects.rs` and `tests/common/grants.rs` are unchanged.

### Quote from the resident SPEC (read only at `35697329be0aad89eb68d0adf78aa94d24751317`)

The status and settler sentences this task takes, from "RI-5 Runtime settlement and the request record":

```text
`status` is `pending`, `granted`, `denied` or `expired`. `settled_by` is
`shell` or `runtime`, and `null` only while pending.
```

This task takes `expired` only. The stop and the failed start stay 052 and 058.

### Quotes from the Runtime (read only, not imported)

`elastos/crates/elastos-runtime/src/capability/pending.rs:16-17` states the default and its value:

```text
/// Default request timeout in seconds (5 minutes)
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;
```

`elastos/crates/elastos-server/src/api/handlers/capability.rs:215-219` states the expired answer:

```text
        elastos_runtime::capability::RequestStatus::Expired => Ok(Json(RequestStatusOutput {
            status: "expired".to_string(),
            token: None,
            reason: Some("Request timed out".to_string()),
        })),
```

### Code

- `REQUEST_TIMEOUT_SECS` is 300 at `standin-runtime/mod.rs:35`, beside `FAILED_KEEP_SECS` at `:34`.
- `RequestStatus` gains `Expired` at `:105`. `request_status_text` at `:807` maps it to `expired` at `:812` and still maps `granted` to `granted` at `:810`. The shell JSON keeps its eight keys `request_id`, `session_id`, `resource`, `action`, `reason`, `status`, `decision_reason` and `settled_by` at `:793-802`; `requested_at` is not a JSON field.
- `Request` gains `requested_at: u64` at `:114`. `seed_request` at `:250` stores `requested_at: self.instant` at `:281` and its validation stays as found. The `Request` literal in `standin_stop_preserves_settled_requests` sets `requested_at` to 0 at `:3720`; its body is otherwise unchanged.
- `set_instant` at `:535` stores the argument and then calls `self.expire_due()` at `:537`; it reads no clock.
- `expire_due` at `:666-685` is private, and its doc comment starts `Not a route.` It selects the `Pending` records whose stored instant minus that record's `requested_at` is at least 300 at `:671-674`, then calls the one writer `settle_record` at `:624` with `expired`, `Request timed out` and `runtime` at `:678-683`. The writer's body is as found, so a second writer does not exist.
- No new public method. `post_capability_grant` at `:404`, `post_capability_deny` at `:364`, `settle_pending` at `:646`, `get_capability_requests` at `:292` (`&self`) and `watch_ended` at `:317` are unchanged.

### Tests

`standin_unanswered_request_expires` at `:3749`, in the module's `#[cfg(test)]`, passes with no operator and no probe build. Every assertion message starts `the stand-in`. The `expired_request` helper sits beside `denied_request` at `:1637`; it expects `status` `expired`, `decision_reason` `Request timed out` and `settled_by` `runtime`.

- The test admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice and finishes both starts, so `component-1` and `component-2` are `running` with cause `""`. It seeds `req-1` on `component-1` and `req-2` on `component-2` at the Public resource, action `read`, reason `read shared`.
- The shell grant of `req-2` with `{"request_id":"req-2","duration":"session","rationale":"grant shared read"}` is Ok `{"success": true}` at instant 0.
- At instant 299 the shell record for `component-1` is `req-1` still `pending` with `settled_by` null.
- At instant 300 that record is `expired_request("req-1", "component-1")`, and `component-1` stays `running` with cause `""`. `component-2`'s record is `req-2` `granted`, `settled_by` `shell`, `decision_reason` `grant shared read`. The shell live-grant `request_id` set is exactly `req-2`.
- A deny of `req-1` with reason `too late` is status 400 with the reason `request is not pending: req-1`, and a grant of `req-1` is that same 400. The expired record stays and the live set stays exactly `req-2`.
- `req-3` is seeded on `component-1` at instant 300 with the same resource, action and reason. At 599 it is still `pending` with `settled_by` null and `req-1` is still the expired record. At 600 `req-3` is `expired_request("req-3", "component-1")` and `req-1` stays the first expired record.
- A denied `req-old` is pushed the way `standin_stop_preserves_settled_requests` does, with `requested_at` 0, and `set_instant(300)` runs. That record stays `denied` with `decision_reason` `denied earlier` and `settled_by` `shell`.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_unanswered_request_expires -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. Each planted crate compiled. Before the plants `sha256sum standin-runtime/mod.rs` was `0b3192cbcf010ce8fe168afe15e1599b52a771ebc64b064ebcb50d64a4a88889`; after the last restore it was the same value, and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows no plant.

F-standin-expire-stub: the start of `expire_due` returns before any request is read. Planted run failed on the assertion at `standin-runtime/mod.rs:3802:9`: `the stand-in expires the unanswered request at 300 seconds with the runtime as settler`; the record was `pending` with `settled_by` null against the expected `expired` record.

Old:

```text
    fn expire_due(&mut self) {
        let instant = self.instant;
```

New:

```text
    fn expire_due(&mut self) {
        return;
        let instant = self.instant;
```

F-standin-expire-late: the age comparison is `>` `REQUEST_TIMEOUT_SECS`. Planted run failed on the same assertion at `standin-runtime/mod.rs:3801:9`; the record at instant 300 stayed `pending` with `settled_by` null.

Old:

```text
                    && instant.saturating_sub(request.requested_at) >= REQUEST_TIMEOUT_SECS
```

New:

```text
                    && instant.saturating_sub(request.requested_at) > REQUEST_TIMEOUT_SECS
```

F-standin-expire-settled: the filter also selects `Denied` records. Planted run failed on the final assertion at `standin-runtime/mod.rs:3891:9`: `the stand-in leaves the settled denied record as its own test stores it`; `req-old` became `expired` with `decision_reason` `Request timed out` and `settled_by` `runtime`.

Old:

```text
                request.status == RequestStatus::Pending
```

New:

```text
                request.status != RequestStatus::Granted
```

### Docs

`standin-runtime/README.md:51` adds the expiry paragraph immediately before `## Callers`: `set_instant` calls `expire_due`, a pending request ages from the instant `seed_request` stored in `requested_at`, and at 300 seconds the one writer sets `expired`, `Request timed out` and `settled_by` `runtime`. A granted or denied record stays, the instance stays, an expired request is not pending, this value is the lab stand-in and the real timeout can replace it later because the status matches (M1-R), and a PASS gives the Runtime no A10 or A11 credit for expiry. The RA-1 section, the RI-1 to RI-4 section, the 061 grant paragraph, the 062 watch paragraph and the 063 survivor paragraph stay as found. `RUNBOOK.md:733` adds one paragraph after the last stand-in paragraph: `standin_unanswered_request_expires` is this stand-in, and a PASS there gives the Runtime no A10 or A11 credit for expiry. No other RUNBOOK paragraph changes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. `Cargo.toml` and `Cargo.lock` are unchanged, and the protected diff is empty: `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 261.21 seconds, inside the 600-second bound. The observed targets were lib 55 passed 0 failed, runtime 10 passed with 2 ignored, standin_contract 2 passed, probe 3 passed and doc-tests 0; the new test passed in the lib target and no `error: test failed` line appeared. Cargo stops at the first failing target, so reaching the last doc-tests target means every earlier target passed. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.15 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_unanswered_request_expires -- --exact` exit 0, real 0.07 seconds, 1 passed and 0 failed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The change adds one status string and a lab age field at `standin-runtime/mod.rs:105,114`; the test seeds stored request ids on the existing Public resource path at `:3749`. No code or content identity is added. |
| 2. Capsule, Home or UI gains ungranted access? | No | `expire_due` at `standin-runtime/mod.rs:666` changes lab request records only; `set_instant` at `:535` is a test seam, and the shell-only routes keep their refusal, so no capsule, Home or UI call path changes. |
| 3. A second path or a second copy of one rule? | No | `expire_due` calls the one writer `settle_record` at `standin-runtime/mod.rs:624`; the writer body is as found and no second writer, route or public method exists. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/`, `capsules/` and `scripts/` are untouched, and the Runtime timeout is quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | The expiry selects only `Pending` records at `standin-runtime/mod.rs:671-674`, and a deny or grant of the expired request is 400 `request is not pending: req-1` through the unchanged route checks at `:379,419`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | No capsule code or import changes; the stand-in keeps the one shell request record the real route answers. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_unanswered_request_expires` at `standin-runtime/mod.rs:3749`; the stub, late and settled plants each fail that named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | Expiry writes one request record at `standin-runtime/mod.rs:678-683` and leaves the instance phase and grants as they were; `finish_start` at `:503` and `delete_capsule` at `:578` stay the admission and stop decisions, and a granted record and its `Live` grant stay. A PASS gives the Runtime no A10 or A11 credit for expiry. |

## 065 — A6: one use spends a once grant

065: `authorise` becomes `&mut self` and, on its one success path, stores `Exhausted` in that grant's `life` when its duration is `once`. The three refusals keep their order, status and reason text and write nothing. `standin_sibling_cannot_use_the_grant` now asserts the refused sibling leaves the grant `Live` and the owner's single use stores `Exhausted`, so the live view drops the grant. The new `standin_once_grant_is_spent_by_one_use` proves the spend and the session grant that stays. `standin-runtime/README.md` states the spend in its `authorise` paragraph, and `RUNBOOK.md` gains one paragraph after the last stand-in paragraph. `elastos/`, `capsules/`, `scripts/`, `examples/`, `GAPS.md`, `falsifiers.json`, `Cargo.toml`, `Cargo.lock`, `src/harness.rs`, `src/census.rs`, `tests/effects.rs` and `tests/common/grants.rs` are unchanged. No new method, use counter, token or reason string.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md:318-320`, "Delegation and mandates":

```text
- **Allow once** authorizes one exact operation.
- **Allow for this session** authorizes a bounded operation set until the
  session ends or the grant is revoked.
```

### Quotes from the Runtime (read only, not imported)

`elastos/crates/elastos-server/src/api/handlers/capability.rs:334-337` shows the two durations this task mirrors:

```text
    let constraints = match duration {
        GrantDuration::Once => TokenConstraints::new(0, false, None, Some(1)),
        GrantDuration::Session => TokenConstraints::default(),
    };
```

`Once` therefore carries `max_uses` `Some(1)`, and `Session` uses the default, which leaves `max_uses` unset.

`elastos/crates/elastos-runtime/src/capability/manager.rs:422-427` checks the caller before the use count:

```text
        // 4. Caller verification
        if token.capsule != caller_capsule_id {
            self.audit_validation_failure(token, caller_capsule_id, "wrong_capsule");
            return Err(ValidationError::WrongCapsule {
                expected: token.capsule.clone(),
                got: caller_capsule_id.to_string(),
            });
```

The use count check is later, at `manager.rs:486-490` (`try_use_token`). A refused caller returns `wrong capsule` before that call, so a refused caller spends no use.

### Code

- `authorise` at `standin-runtime/mod.rs:460` takes `&mut self`; its doc comment starts `Lab test seam, not a route.` and states that a `once` grant stores `Exhausted`. The unknown id, the not-live life and the wrong caller return in that order with the same status and reason text.
- The one write is at `standin-runtime/mod.rs:475-477`: on success, `grant.duration == "once"` sets `self.grants[index].life = Life::Exhausted`. Every other field and every other grant stay. A `session` grant stays `Live`. The refusals write nothing. There is no use counter and no second reason; a spent grant's next presentation is the existing `grant is not live: Exhausted`.
- `seed_grant`, `seed_at`, `is_live`, `revoke_live`, `keep`, `visible`, `post_capability_grant`, `post_capability_deny`, `watch_ended` and `expire_due` are unchanged. No new `StandIn` method.

### Tests

`standin_once_grant_is_spent_by_one_use` at `standin-runtime/mod.rs:4663`, in the module's `#[cfg(test)]`, passes with no operator and no probe build. Every assertion message starts `the stand-in did the work:`.

- `launch_two_running` gives `component-1` and `component-2` `running`. `req-once` is seeded on `component-1` and `req-session` on `component-2`, resource `res`, action `read`, `granted_at` 1, life `Live`, `session_ended` false, durations `once` and `session`. The shell `request_id` set is exactly both.
- The `component-2` client's `authorise` of `req-once` is 403 `wrong capsule`, and the shell's is 403 `wrong capsule`. `grant_record` for `req-once` stays `(Life::Live, false)` and the shell set stays both.
- The `component-1` client's `authorise` of `req-once` is `Ok(())`; `grant_record` becomes `(Life::Exhausted, false)` and the shell set is exactly `req-session`.
- A second `authorise` by the `component-1` client is 400 `grant is not live: Exhausted`.
- Two `authorise` calls by the `component-2` client of `req-session` are each `Ok(())`; `grant_record` stays `(Life::Live, false)` and the shell set stays exactly `req-session`.
- Both instances stay `running` with cause `""`.

`standin_sibling_cannot_use_the_grant` at `:4564` keeps its launch, seed, shell list before any `authorise`, sibling 403, owner `Ok(())` and both instance checks. It adds the sibling-refusal record `(Life::Live, true)` and the still-`req-1` shell set, and its final assertion is now `(Life::Exhausted, true)` with an empty shell set; the text `the stand-in leaves the seeded grant unchanged` is gone. `standin_stop_clears_that_sessions_grant`, `standin_authorise_unknown_grant`, `standin_authorise_dead_grants` and `standin_shell_cannot_authorise` keep their bodies; their one-use successes are not followed by a life read.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone and was restored before the next. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_once_grant_is_spent_by_one_use -- --exact` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. Each planted crate compiled. After the last restore, `standin-runtime/mod.rs` matched the pre-plant copy byte for byte and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows only the intended change, with no plant. The restored file's SHA-256 is `05ad138ccd4bc492cd8dc7b4fc490697000189e4871864f7b97dfe361fef8959`.

F-standin-a6-once-stub: the start of `authorise` returns `Ok(())` before any grant is read. Planted run failed on the assertion at `standin-runtime/mod.rs:4552:9`: `the stand-in did the work: it refuses the sibling of the once grant: Ok(())`.

Old:

```text
    pub fn authorise(&mut self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        let Some(index) = self
```

New:

```text
    pub fn authorise(&mut self, caller: Caller<'_>, request_id: &str) -> Result<(), (u16, String)> {
        return Ok(());
        let Some(index) = self
```

F-standin-a6-once-keep: the success path does not change `life`. Planted run failed on the assertion at `standin-runtime/mod.rs:4727:9`: `the stand-in did the work: the owner's one use stores Exhausted`, left `(Live, false)`, right `(Exhausted, false)`.

Old:

```text
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        if grant.duration == "once" {
            self.grants[index].life = Life::Exhausted;
        }
        Ok(())
```

New:

```text
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        Ok(())
```

F-standin-a6-once-session: the success path also sets a `session` grant to `Exhausted`. Planted run failed on the assertion at `standin-runtime/mod.rs:4758:13`: `the stand-in did the work: session grant use 2 succeeds: Err((400, "grant is not live: Exhausted"))`.

Old:

```text
        if grant.duration == "once" {
            self.grants[index].life = Life::Exhausted;
        }
```

New:

```text
        if grant.duration == "once" || grant.duration == "session" {
            self.grants[index].life = Life::Exhausted;
        }
```

F-standin-a6-once-sibling: the `Exhausted` store runs before the session check. Planted run failed on the assertion at `standin-runtime/mod.rs:4552:9`: `the stand-in did the work: it refuses the shell presentation of the once grant: Err((400, "grant is not live: Exhausted"))`.

Old:

```text
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        if grant.duration == "once" {
            self.grants[index].life = Life::Exhausted;
        }
        Ok(())
```

New:

```text
        let exhausted = grant.duration == "once";
        if exhausted {
            self.grants[index].life = Life::Exhausted;
        }
        if !session_authorises(&self.grants[index], caller) {
            return Err(wrong_capsule(&self.grants[index], caller));
        }
        Ok(())
```

### Docs

`standin-runtime/README.md:33` keeps the `authorise` paragraph with the sibling refusal and the stop. It adds that a successful `authorise` by the owning client of a `once` grant stores `Exhausted`, that the live view omits it through the one life filter, that a `session` grant stays `Live`, and that a refusal spends nothing. The RA-1 section and the RI-1 to RI-4 material stay, and the paragraph stays before `## Callers`. `RUNBOOK.md:735` adds one paragraph after the last stand-in paragraph: `standin_once_grant_is_spent_by_one_use` is this stand-in, and a PASS there gives the Runtime no A6 credit for a once grant. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged, and the protected diff is empty: `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 245.91 seconds, inside the 600-second bound. The observed targets were lib 56 passed 0 failed (a separate `--lib` run), effects passed (Cargo reached the later targets), report 23 passed, runtime 10 passed with 2 ignored, standin_contract 2 passed, probe 3 passed and doc-tests 0; no `error: test failed` line appeared. Cargo stops at the first failing target, so reaching the last doc-tests target means every earlier target passed. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.13 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_once_grant_is_spent_by_one_use -- --exact` exit 0, real 0.06 seconds, 1 passed and 0 failed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The change adds no identity; `authorise` at `standin-runtime/mod.rs:460` and the test at `:4663` use existing lab request ids and the seeded `res` resource. |
| 2. Capsule, Home or UI gains ungranted access? | No | The edit changes one lab grant's life at `standin-runtime/mod.rs:475-477`; no capsule, route or import changes, and the shell still holds no grant. |
| 3. A second path or a second copy of one rule? | No | `authorise` at `standin-runtime/mod.rs:460` stays the one presentation check; the spend is inside its success path at `:475`, with no new method, use counter or reason string. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/`, `capsules/` and `scripts/` are untouched, and the Runtime durations are quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | The unknown-id, not-live and wrong-caller refusals at `standin-runtime/mod.rs:466-473` keep status 400/403 and their existing reasons; a spent grant's next use is 400 `grant is not live: Exhausted`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | No capsule code or import changes; the stand-in keeps the one presentation check the Runtime uses, and the capsule keeps its own logic. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_once_grant_is_spent_by_one_use` at `standin-runtime/mod.rs:4663`; the stub, keep, session and sibling plants each fail that named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The caller decision at `standin-runtime/mod.rs:472` and the liveness decision at `:469` come before the duration-limited spend at `:475`; the Runtime checks the caller at `manager.rs:422-427` before `try_use_token` at `:486`, so a refused caller spends nothing in either place. A PASS gives the Runtime no A6 credit for a once grant. |

## 066 — A10: an ended instance cannot make a request

066: `StandIn` gains one route, `post_capability_request(caller, body) -> Result<Value, (u16, String)>` at `standin-runtime/mod.rs:320`. Its doc comment starts `POST /api/capability/request.` A shell caller is status 403 with `capability request needs an instance session` before the body is read. The one body parser `request_body` at `:1096` accepts only `resource`, `action` and `reason`; a missing or non-string `resource` or `action`, a non-string `reason`, or an extra key is status 400 with the named reason, and a missing `reason` is `""`. A resource without `elastos://` or `localhost://` is status 400 with `Unsupported resource scheme. Allowed: elastos://, localhost://`; an action whose lowercase form is not one of the six names is status 400 with `Invalid action: ` plus the given text plus `. Expected: read, write, execute, delete, message, admin`. The method then looks up the stored instance by `id`, the way `finish_start` does, and refuses an unknown id with `unknown_instance` or any stored phase other than `Starting` or `Running` with `not_live`. On success it mints `request-` plus the new `next_request` counter (`:126`, starts at 1 at `:138`), calls `seed_request` once for the caller's `session_id` with the resource, the lowercase action and the reason, and advances the counter only after `Ok`. It returns `{"status":"pending","request_id":...}` with no token and stores no grant. `seed_request`, `get_capability_requests`, `settle_pending`, `stop_one`, `finish_start`, `delete_capsule`, `not_live`, `unknown_instance`, `post_capability_grant`, `post_capability_deny`, `watch_ended`, `expire_due` and `authorise` keep their bytes. The instance counter stays separate: two launches still answer `component-1` and `component-2`.

### Quote from the resident SPEC (read only)

> later Bus calls from it are refused.

The stop still ends the instance and revokes its grants; this route adds the later-call refusal for a new capability request.

### Quote from the Runtime route (read only, `elastos/crates/elastos-server/src/api/handlers/capability.rs`)

> The body keys are `resource`, `action` and `reason`. The caller is the authenticated session. A request with no auto-grant returns `status` `pending` and `request_id`, and no token.

The stand-in keeps the `pending` plus `request_id` shape and adds no token. It does not copy the system-backend or wallet branch.

### Tests

Three tests in `standin_runtime::tests`, each passing with no operator and no probe build. They reuse `pending_request`, `request_entries`, `shell_requests`, `get_capability_list`, `request_ids`, `assert_capsule`, `admit_shared`, `launch_finished`, `stop_body` and `SHARED_RESOURCE`; assertion text says the stand-in did the work.

- `standin_ended_instance_request_is_refused` (`:5238`) admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice and finishes both starts, so `component-1` and `component-2` are `running`. It deletes `component-1` with `{"reason":"stop one"}`. The client body is `{"resource":"localhost://Public/resident-instances/shared.txt","action":"read","reason":"read shared"}`. The `component-1` call is status 400 `instance is not live: stopped`, and its shell record is `{"requests":[]}`. At instant 60 the same call is still that 400 and the record is still empty. The `component-2` call is Ok `{"status":"pending","request_id":"request-1"}`, its shell record is `pending_request("request-1", "component-2")`, the shell live-grant `request_id` set is empty, and `component-2` stays `running` with cause `""`. A `component-9` call is status 400 `unknown instance: component-9`, and the `component-2` record stays that one pending request. A second `StandIn` admits `/capsules/fail-after-submit` as `fail-after-submit` with `Start::Error("start refused")`, launches once, and finishes the start: the same body is status 400 `instance is not live: failed`, the shell record is empty, and the list entry stays `failed` with cause `start refused`.
- `standin_live_instance_request_stays_pending` (`:5397`) admits the same path and launches once without `finish_start`: `component-1` is `starting`. The shell caller with a null body is status 403 `capability request needs an instance session`, and the shell record is empty. The client call is Ok `{"status":"pending","request_id":"request-1"}`, the record is `pending_request("request-1", "component-1")`, the phase stays `starting` with cause `""`, and the live-grant set is empty. After `finish_start("component-1")`, a second client call with `"action":"Write"` is Ok `{"status":"pending","request_id":"request-2"}`; the record holds `request-1` and `request-2`, both `pending`, and `request-2`'s action is `write`; the phase stays `running`.
- `standin_capability_request_refuses_a_bad_body` (`:5496`) uses one starting instance. A client body `{}` is `request body needs resource`; `{"resource":"https://example","action":"read"}` is the unsupported-scheme reason; `{"resource":"localhost://Public/resident-instances/shared.txt","action":"mint"}` is `Invalid action: mint. Expected: read, write, execute, delete, message, admin`; a body with the extra key `token` is `request body rejects token`. The shell record stays empty, and the valid body is then Ok `request-1`, so the refused bodies do not advance the counter.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `env RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_ended_instance_request_is_refused -- --exact`. The planted crate compiled every time, and every planted run exited 101. After the last restore, `sha256sum standin-runtime/mod.rs` was `2113d941c669f88af8a20b8932b57f8001470899f66388019757435b036f6156`, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only, and no plant expression remained. No `falsifiers.json` id was added.

F-standin-request-stub. Assertion: `src/../standin-runtime/mod.rs:5275:9` `assertion left == right failed: the stand-in did the work: it refuses a new request from the stopped instance`, `left: Ok(Object {"request_id": String("request-1"), "status": String("pending")})`, `right: Err((400, "instance is not live: stopped"))`.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        let Caller::Client { session_id } = caller else {
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "status": "pending", "request_id": "request-1" }));
        let Caller::Client { session_id } = caller else {
```

F-standin-request-ended. Assertion: `src/../standin-runtime/mod.rs:5277:9` `assertion left == right failed: the stand-in did the work: it refuses a new request from the stopped instance`, `left: Ok(Object {"request_id": String("request-1"), "status": String("pending")})`, `right: Err((400, "instance is not live: stopped"))`.

Old:

```text
            .map(|instance| instance.phase)
            .ok_or_else(|| unknown_instance(session_id))?;
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
```

New:

```text
            .map(|instance| instance.phase)
            .ok_or_else(|| unknown_instance(session_id))?;
        if !matches!(
            phase,
            ResidentStatus::Starting | ResidentStatus::Running | ResidentStatus::Stopped
        ) {
```

F-standin-request-sibling. Assertion: `src/../standin-runtime/mod.rs:5313:9` `assertion left == right failed: the stand-in did the work: it stores one pending request for component-2`, `left: []`, `right: [Object {... "session_id": String("component-2"), "status": String("pending") ...}]`.

Old:

```text
        self.seed_request(&request_id, session_id, resource, &action, reason)?;
```

New:

```text
        self.seed_request(&request_id, "component-1", resource, &action, reason)?;
```

### Docs

`standin-runtime/README.md:53` adds one paragraph immediately before `## Callers`: `post_capability_request` answers `POST /api/capability/request`; it calls `seed_request` only for a `starting` or `running` instance, and a `stopped` or `failed` instance is `instance is not live` and stores nothing; the Ok body is `status` `pending` and `request_id`, with no token; `seed_request` can still store a record after the end; a PASS gives the Runtime no A10 credit for this refusal. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph and the watch, survivor, expiry and once-grant paragraphs keep their bytes. `RUNBOOK.md:737` adds one paragraph after the last stand-in paragraph: `standin_ended_instance_request_is_refused` is this stand-in, and a PASS there gives the Runtime no A10 credit for a new request. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged; `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.165 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 258 seconds, inside the 600-second bound. Targets in order: lib 59 passed; one-target 1 passed; effects 7 passed; artifact 1 passed; runtime 61 passed with 12 ignored; standin_contract 9 passed; report 23 passed; report 10 passed with 2 ignored; 2 passed; 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_ended_instance_request_is_refused -- --exact` exit 0, 1 passed and 0 failed.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The route stores the caller's `session_id` and the requested resource text at `standin-runtime/mod.rs:359-361`; it adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | A client instance gains one pending request record through `seed_request` at `:360`; no grant, token or resource access is minted, and a shell is refused at `:326`. |
| 3. A second path or a second copy of one rule? | No | The success path calls `seed_request` and no other writer at `:360`; `request_body` at `:1096` is the one body rule, and the stored record is read through `get_capability_requests`. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/`, `capsules/` and `scripts/` are untouched, and the Runtime route is quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | Shell, body, scheme, action, unknown-instance and not-live refusals return 400/403 with the named reason at `:326`, `:1096-1141`, `:332`, `:342`, `:355` and `:357`, and each stores nothing. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The instance stores its request through one granted route while `starting` or `running`; no capsule code or import changes. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `:5238`, `:5397` and `:5496`; the stub, stopped-phase and sibling plants each fail the named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The caller identity check at `:326`, admission through `finish_start` (unchanged), and the liveness gate at `:356` come before the request record; storing a request grants no allowance, and the counter is separate from the instance counter. |

A passing row gives the real Runtime no A10 credit for this refusal.

## 067 — A11: guest reads the decision on a later call

067: `StandIn` gains one read route, `get_capability_request(&self, caller, request_id: &str) -> Result<Value, (u16, String)>` at `standin-runtime/mod.rs:503`. Its doc comment starts `GET /api/capability/request/:id.` The id is the path, a method argument, not a JSON field. The lookup runs before the caller check: an id that matches no record is status 404 with `Request not found: ` plus that id; a shell caller, or a client whose `session_id` is not the record's, is status 403 with `Cannot access another session's request`. Each refusal stores nothing. The status word comes from `request_status_text` at `:903`. A `pending` or `granted` word returns a body whose only key is `status`; a `denied` or `expired` word returns `status` and `reason`, where `reason` is the record's `decision_reason`. The body has no `token`, no `request_id` and no `success`. `seed_request`, `get_capability_requests`, `request_entry`, `request_status_text`, `settle_record`, `settle_pending`, `post_capability_grant`, `post_capability_deny`, `stop_one`, `finish_start`, `authorise`, `watch_ended`, `expire_due` and `post_capability_request` keep their bytes; no request store, status renderer or other method was added.

### Quote from the resident SPEC (read only)

`git show 35697329be0aad89eb68d0adf78aa94d24751317:lab/resident-instances/SPEC.md`, heading `### RI-6 A pending request outlives the guest's call`:

> The RI-1 world lets a guest submit a capability request and continue before the decision. The decision reaches the guest later, as an event or through a later call.

This task takes the later call. The submit route stays 066, and the settlement of a failed start stays 058.

### Quote from the ask (read only)

`git show 513988ebd:lab/runtime-asks/07-pending-request-outlives-call.md`, `## The ask`:

> A guest can submit a capability request and continue before the decision. The Runtime records the pending request before the submit call returns. The decision reaches the guest later.

Option 1 is this later call. Option 2, the instance deadline, and the per-session cap of 32 are not this task.

### Quote from the Runtime route (read only, `elastos/crates/elastos-server/src/api/handlers/capability.rs`)

`request_status` at `:162`:

> ```rust
>     let request = state
>         .pending_store
>         .get_request(&request_id)
>         .await
>         .ok_or_else(|| {
>             (
>                 StatusCode::NOT_FOUND,
>                 format!("Request not found: {}", request_id),
>             )
>         })?;
>
>     // Verify the request belongs to this session
>     if request.session_id != session.id {
>         return Err((
>             StatusCode::FORBIDDEN,
>             "Cannot access another session's request".to_string(),
>         ));
>     }
> ```

The lookup runs before the session check, so a missing record is 404 for any caller. `pending` sets `token: None` and `reason: None`. `denied` carries the decision reason and `token: None`. The real `granted` arm also returns a token. The stand-in copies the refusals and the status shape, stores no token, and does not copy the system-backend, wallet or auto-grant branch.

### Tests

Two tests in `standin_runtime::tests`, each passing with no operator and no probe build. They reuse `pending_request`, `granted_request`, `denied_request`, `seed_shared_request`, `request_entries`, `shell_requests`, `get_capability_list`, `request_ids`, `assert_capsule`, `assert_live_request_ids_empty`, `admit_shared`, `launch_finished`, `stop_body` and `SHARED_RESOURCE`; assertion text says the stand-in did the work.

- `standin_guest_reads_its_request_later` (`:5608`) admits `/capsules/read-shared` as `read-shared` with `Start::Ok` and launches twice: `component-1` and `component-2`, both `starting`. It seeds `req-1` on `component-1` and `req-2` on `component-2` with resource `localhost://Public/resident-instances/shared.txt`, action `read` and reason `read shared`. The `component-1` client and `req-1` is Ok `{"status":"pending"}`. The shell caller and `req-1` is status 403 `Cannot access another session's request`, as is the `component-2` client and `req-1`; the `component-2` client and `missing` is status 404 `Request not found: missing`. The refused reads leave both shell records pending. At instant 4 the shell grant of `req-1` with `duration` `session` and rationale `grant shared read` is Ok `{"success":true}`; the `component-1` client and `req-1` is then Ok `{"status":"granted"}`, and a second read is the same body. The shell record is `granted_request("req-1","component-1","grant shared read")`, and the shell live-grant `request_id` set is exactly `req-1`. The shell deny of `req-2` with reason `sibling read denied` is Ok `{"success":true}`; the `component-2` client and `req-2` is Ok `{"status":"denied","reason":"sibling read denied"}`, and the `component-1` client and `req-2` is the 403 above. The deny fails the starting sibling with that cause; the reads leave the phases as the deny stored them (`component-1` `starting`, `component-2` `failed`), and leave the live-grant set exactly `req-1`.
- `standin_guest_reads_a_runtime_denial` (`:5766`) admits the same path, launches and finishes twice so both are `running`, and seeds `req-1` on `component-1` only. It deletes `component-1` with `{"reason":"stop one"}`. The `component-1` client and `req-1` is Ok `{"status":"denied","reason":"stopped: stop one"}` both before and after `set_instant(60)`. The `component-2` client and the shell caller are the 403 above. The shell record is still `denied_request("req-1","component-1","stopped: stop one")`, and no grant is live.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `env RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_guest_reads_its_request_later -- --exact`. The planted crate compiled every time (`Compiling agent-conformance` then `Finished`), and every planted run exited 101 with that test failed on its assertion. After the last restore, `sha256sum standin-runtime/mod.rs` was `d9be9499c36a6e8f068548826ca5a9100c3cd20c032938d20bb0fafeebddc6bb`, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only, and no plant expression remained. No `falsifiers.json` id was added.

F-standin-status-stub. Assertion: `src/../standin-runtime/mod.rs:5637:9` (restored assertion `:5636`) `assertion left == right failed: the stand-in did the work: the owning client reads req-1 pending before any decision`, `left: Ok(Object {"status": String("granted")})`, `right: Ok(Object {"status": String("pending")})`.

Old:

```text
    pub fn get_capability_request(
        &self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        let Some(request) = self
```

New:

```text
    pub fn get_capability_request(
        &self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "status": "granted" }));
        let Some(request) = self
```

F-standin-status-sibling. Assertion: `src/../standin-runtime/mod.rs:5594:9` (restored assertion `:5600`) `assertion left == right failed: the stand-in did the work: it refuses the shell caller on another session's request (req-1 is the client's record)`, `left: Ok(Object {"status": String("pending")})`, `right: Err((403, "Cannot access another session's request"))`.

Old:

```text
        let owns = matches!(
            caller,
            Caller::Client { session_id } if session_id == request.session_id
        );
        if !owns {
            return Err((403, "Cannot access another session's request".to_owned()));
        }
```

New:

```text
        let _ = caller;
```

F-standin-status-token. Assertion: `src/../standin-runtime/mod.rs:5687:9` (restored assertion `:5683`) `assertion left == right failed: the stand-in did the work: the owning client reads req-1 granted on a later call`, `left: Ok(Object {"status": String("granted"), "token": String("req-1")})`, `right: Ok(Object {"status": String("granted")})`.

Old:

```text
            RequestStatus::Pending | RequestStatus::Granted => Ok(json!({ "status": status })),
```

New:

```text
            RequestStatus::Pending => Ok(json!({ "status": status })),
            RequestStatus::Granted => Ok(json!({
                "status": status,
                "token": "req-1",
            })),
```

### Docs

`standin-runtime/README.md:55` adds one paragraph immediately before `## Callers`: `get_capability_request` answers `GET /api/capability/request/:id`; it reads the one request store; the owning client receives `pending` or `granted` as a body whose only key is `status`; a denied or expired record also carries `reason`; a shell or a sibling is `Cannot access another session's request`; a missing record is 404 with `Request not found: ` plus that id; there is no token; the read stores nothing; a PASS gives the Runtime no A11 credit for this later call. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph and the watch, survivor, expiry, once-grant and request-route paragraphs keep their bytes. `RUNBOOK.md:739` adds one paragraph after the last stand-in paragraph: `standin_guest_reads_its_request_later` is this stand-in, and a PASS there gives the Runtime no A11 credit for a later read. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged; `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.145 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 4m17.285s (257.28 seconds), inside the 600-second bound. Targets: lib 61 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; runtime 61 passed with 12 ignored; harness 9 passed; report 23 passed; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_guest_reads_its_request_later -- --exact` exit 0, 1 passed and 0 failed, real 0.781 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The read uses the stored `request_id` as the path at `standin-runtime/mod.rs:503-514`; it adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The owning client gains a read of its own request record and no grant, token or resource access; the shell and a sibling are refused at `:515-521`. |
| 3. A second path or a second copy of one rule? | No | The one store is looked up the way `settle_record` at `:720` does; the word comes from `request_status_text` at `:903`; the list route and `request_entry` are not called or copied. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and its route is quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | A missing record is 404 `Request not found: ` plus the id at `:513`; a shell or another session is 403 `Cannot access another session's request` at `:515-521`; each refusal returns before any write. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The guest reads its own decision through one Runtime route; no capsule code, import or world changes. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `:5608` and `:5766`; the stub, removed-session-check and extra-token plants each fail the named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The lookup at `:508` and the caller identity check at `:515` precede any body; the read settles nothing and mints no grant, so an identity match never implies allowance, and `granted` is only the stored decision. |

A passing row gives the real Runtime no A11 credit for this later call.


## 068 — A11: one session holds at most 32 pending requests

068: `standin-runtime/mod.rs` gains one constant, `MAX_PENDING_PER_SESSION: usize = 32` at `:36`, beside `REQUEST_TIMEOUT_SECS` at `:35`. `seed_request` at `:255` counts that session's `Pending` records at `:280-286`, after the empty-field refusal at `:263-271` and the duplicate-id refusal at `:273-278`, and before the push at `:290`. At 32 the call returns `Err((400, "Too many pending requests for this session"))` at `:287-289` and pushes nothing. A `Granted`, `Denied` or `Expired` record does not count, and no record of another session counts. `post_capability_request` at `:332` is unchanged: `self.seed_request(...)?` at `:372` returns that status and reason, and `next_request += 1` at `:373` runs only after `Ok`. The route counts nothing. One store, one counter, one reason.

### Quote from the ask (read only)

`git show 513988ebd:lab/runtime-asks/07-pending-request-outlives-call.md`, `## Risks`, the bullet `A guest that never reads the decision`, `:77`:

> Until then the per-session cap of 32 pending requests applies (`pending.rs:24`).

This task takes that cap. The guest's later read stays 067, and the submit route stays 066.

### Quote from the Runtime store (read only, `elastos/crates/elastos-runtime/src/capability/pending.rs`)

The constant at `:24`:

> ```rust
> pub const MAX_PENDING_PER_SESSION: usize = 32;
> ```

The per-session block in `create_request_with_reason` counts only the `Pending` records of that session at `:289-296`:

> ```rust
>                 let pending_count = ids
>                     .iter()
>                     .filter(|id| {
>                         requests
>                             .get(*id)
>                             .is_some_and(|r| matches!(r.status, RequestStatus::Pending))
>                     })
>                     .count();
> ```

At 32 the next request is not inserted, and the reason is `Too many pending requests for this session` at `:297-307`:

> ```rust
>                 if pending_count >= MAX_PENDING_PER_SESSION {
>                     let mut request = PendingCapabilityRequest::new_with_reason(
>                         session_id.clone(),
>                         resource.clone(),
>                         action,
>                         reason.clone(),
>                         self.timeout_secs,
>                     );
>                     request.status = RequestStatus::Denied {
>                         reason: "Too many pending requests for this session".to_string(),
>                     };
> ```

The global capacity of 1024 at `:21` stays out of this task, and the stand-in keeps no such limit.

### Quote from the contract (read only, `docs/AGENT_ARCHITECTURE.md`, "Request flow", step 8 at `:235-236`)

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

One session's cap leaves the sibling's request able to be recorded.

### Tests

One test in `standin_runtime::tests`, passing with no operator and no probe build. It reuses `pending_request`, `request_entries`, `granted_request`, `request_ids`, `get_capability_list`, `assert_live_request_ids_empty`, `assert_capsule`, `admit_shared`, `launch_finished`, `post_capability_grant` and `request_client_body`; every assertion says the stand-in did the work.

- `standin_session_pending_cap` (`:5608`) admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice and finishes both starts, so `component-1` and `component-2` are `running`. The client body is `{"resource":"localhost://Public/resident-instances/shared.txt","action":"read","reason":"read shared"}`. Thirty-two `post_capability_request` calls for the `component-1` client are Ok with `request_id` `request-1` through `request-32` and `status` `pending`. The shell record for `component-1` equals `pending_request` for those 32 ids in text order, each `pending` with `settled_by` null. The 33rd call is status 400 with `Too many pending requests for this session`, and the record keeps that same list. The `component-2` client call is Ok `{"status":"pending","request_id":"request-33"}` and its shell record is `pending_request("request-33", "component-2")`. The shell live-grant `request_id` set is empty. `post_capability_grant` as the shell with `{"request_id":"request-1","duration":"session","rationale":"grant shared read"}` is Ok `{"success":true}`; the shell record then holds `request-1` as `granted_request` with `shell` and that rationale, and the other 31 stay `pending`; the live-grant set is exactly `request-1`. The next `component-1` call is Ok `{"status":"pending","request_id":"request-34"}`, and that session's pending set is `request-2` through `request-32` plus `request-34`, with 33 records in all. The following `component-1` call is status 400 with the same reason, the record stays 33, no `request-35` is stored, and `request-34` stays `pending`. The `component-2` record stays the one pending `request-33`. Both instances stay `running` with cause `""`.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `env RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_session_pending_cap -- --exact`. The planted crate compiled every time, and every planted run exited 101. After the last restore, `sha256sum standin-runtime/mod.rs` was `92dfd77fd6cf4416f8b3f3ac7b7c31be4c400f269cc8114c4d3009b4a8905ba5`, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only, and no plant expression remained. No `falsifiers.json` id was added.

F-standin-cap-stub. Assertion: `src/../standin-runtime/mod.rs:5665:9` `assertion \`left == right\` failed: the stand-in did the work: the 33rd pending record of component-1 is refused`, `left: Ok(Object {"request_id": String("request-33"), "status": String("pending")})`, `right: Err((400, "Too many pending requests for this session"))`.

Old:

```text
            return Err((400, format!("request already stored: {request_id}")));
        }
        let pending = self
            .requests
            .iter()
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .count();
        if pending >= MAX_PENDING_PER_SESSION {
            return Err((400, "Too many pending requests for this session".to_owned()));
        }
        self.requests.push(Request {
```

New:

```text
            return Err((400, format!("request already stored: {request_id}")));
        }
        self.requests.push(Request {
```

F-standin-cap-settled. Assertion: `src/../standin-runtime/mod.rs:5733:9` `assertion \`left == right\` failed: the stand-in did the work: the granted record frees one slot for request-34`, `left: Err((400, "Too many pending requests for this session"))`, `right: Ok(Object {"request_id": String("request-34"), "status": String("pending")})`.

Old:

```text
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .count();
```

New:

```text
            .filter(|request| request.session_id == session_id)
            .count();
```

F-standin-cap-sibling. Assertion: `src/../standin-runtime/mod.rs:5685:9` `assertion \`left == right\` failed: the stand-in did the work: the sibling session stores the next request`, `left: Err((400, "Too many pending requests for this session"))`, `right: Ok(Object {"request_id": String("request-33"), "status": String("pending")})`.

Old:

```text
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .count();
```

New:

```text
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
```

### Docs

`standin-runtime/README.md:57` adds one paragraph immediately before `## Callers`: `seed_request` holds at most 32 pending records for one session; the next one is status 400 with `Too many pending requests for this session` and stores nothing; a granted, denied or expired record does not count and a sibling session still stores its request; `post_capability_request` returns that status and reason and counts nothing; a PASS gives the Runtime no A11 credit for this cap. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph and the watch, survivor, expiry, once-grant, request-route and later-read paragraphs keep their bytes. `RUNBOOK.md:741` adds one paragraph after the last stand-in paragraph: `standin_session_pending_cap` is this stand-in, and a PASS there gives the Runtime no A11 credit for the pending cap. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged; `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.178 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 4m15.048s (255.05 seconds), inside the 600-second bound. Targets in order: lib 62 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.178 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_session_pending_cap -- --exact` exit 0, 1 passed and 0 failed, real 0.133 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The cap counts stored `request_id` records at `standin-runtime/mod.rs:280-286` and adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The cap only refuses a pending record at `:287-289`; it mints no grant, token or resource access, and Home holds nothing new. |
| 3. A second path or a second copy of one rule? | No | The one count lives in `seed_request` at `:280-286`, and `post_capability_request` reaches it through `self.seed_request(...)?` at `:372`; no other method counts pending records. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and its store is quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | The 33rd pending record of a session returns 400 `Too many pending requests for this session` at `:287-289` and pushes nothing at `:290`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The change stores or refuses one record in the stand-in's request store; no capsule code, import or world changes. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_session_pending_cap` at `:5608`; the stub, settled-record and sibling plants each fail that test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The count matches the record's `session_id` at `:284` and the phase gate at `:362-370` stays separate; a granted record frees one slot and mints no allowance by itself. |

A passing row gives the real Runtime no A11 credit for this cap.

## 069 — A6: shell revoke drops one live grant

069: `delete_capability` answers `DELETE /api/capability/:id` on the same `StandIn`. It calls `require_shell` before it reads the request store, refuses a missing record with 404 and a record that is not granted with 400, and calls the one writer with `denied`, `Revoked by user` and `shell`. It then calls the one life function for that id, so that id's `Live` grant becomes `Revoked` while the instance and every other grant stay. The one `Revoked` assignment moved out of `revoke_live` into `revoke_grant`; `revoke_live` now calls it for each `Live` grant of the session. `standin_shell_revoke_drops_one_live_grant` and `standin_shell_revoke_refuses_without_a_grant` prove the route. `standin-runtime/README.md` states the route and its refusals, and `RUNBOOK.md` gains one paragraph after the last stand-in paragraph. `elastos/`, `capsules/`, `scripts/`, `examples/`, `GAPS.md`, `falsifiers.json`, `Cargo.toml`, `Cargo.lock`, `src/harness.rs`, `src/census.rs`, `tests/effects.rs` and `tests/common/grants.rs` are unchanged.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md:318-320`, "Delegation and mandates":

```text
- **Allow once** authorizes one exact operation.
- **Allow for this session** authorizes a bounded operation set until the
  session ends or the grant is revoked.
```

This task takes the revoke half of the second sentence: one session grant stops authorising while its instance keeps running. The one use of a `once` grant stays 065, and a standing mandate stays out.

### Quotes from the Runtime (read only, not imported)

`elastos/crates/elastos-server/src/api/server.rs:264` puts the route on the shell router:

```text
        .route("/api/capability/:id", delete(handlers::revoke_capability))
```

`elastos/crates/elastos-server/src/api/handlers/capability.rs:467-485` shows the path argument and the missing-record refusal:

```text
/// DELETE /api/capability/:id
///
/// Revoke a specific capability by request ID (shell only).
pub async fn revoke_capability(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Path(request_id): Path<String>,
) -> Result<Json<RevokeCapabilityOutput>, (StatusCode, String)> {
    // Get the request to find the token
    let request = state
        .pending_store
        .get_request(&request_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Capability request not found: {}", request_id),
            )
        })?;
```

`capability.rs:488-509` shows the granted arm and the other-status refusal:

```text
    // Check if it was granted
    match &request.status {
        elastos_runtime::capability::RequestStatus::Granted { token, .. } => {
            // Revoke the token
            state
                .capability_manager
                .revoke(*token.id(), "Revoked by user via API")
                .await;

            // Mark the request as revoked in the pending store
            state.pending_store.revoke_request(&request_id).await;

            Ok(Json(RevokeCapabilityOutput {
                success: true,
                revoked_request_id: request_id,
                error: None,
            }))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Capability {} was not granted", request_id),
        )),
    }
```

The Ok body's keys are `success` and `revoked_request_id`; `error` is skipped while it is `None` (`capability.rs:460-465`). `elastos/crates/elastos-server/src/api/middleware.rs:90-95` answers a client with status 403 and the reason `This endpoint requires shell privileges`. `elastos/crates/elastos-runtime/src/capability/pending.rs:525-531` sets a granted record to denied with the reason `Revoked by user`:

```text
    pub async fn revoke_request(&self, request_id: &str) {
        let mut requests = self.requests.write().await;
        if let Some(request) = requests.get_mut(request_id) {
            if request.is_granted() {
                request.status = RequestStatus::Denied {
                    reason: "Revoked by user".to_string(),
                };
```

The stand-in copies the refusals, the store reason and the two Ok keys. It does not copy the token, the epoch or the handler's `Revoked by user via API` reason.

### Code

- `delete_capability` at `standin-runtime/mod.rs:554`; its doc comment starts `DELETE /api/capability/:id.` at `:544`. The id is a method argument. `require_shell(caller)?` at `:559` runs before the request store is read at `:560-564`. A missing record is 404 `Capability request not found: ` plus that id at `:565`. A record whose status is not `Granted` is 400 `Capability ` plus that id plus ` was not granted` at `:567-569`; this one branch covers `pending`, `denied` and `expired` and writes nothing. On success the one writer at `:570-575` stores `Denied`, `Revoked by user` and `shell`; `revoke_grant(request_id)` at `:576` drops that id's live grant. The Ok value at `:577-580` has only `success` and `revoked_request_id`.
- `revoke_grant` at `standin-runtime/mod.rs:770` is the only new private function and holds the one assignment `grant.life = Life::Revoked` at `:776`. It matches that id only while its life is `Live`; a missing grant is a no-op and another life stays.
- `revoke_live` at `:757` keeps its contract: it collects that session's `Live` grant ids and calls `revoke_grant` for each, so every `Live` grant of the session becomes `Revoked` and every other life stays. It no longer writes the assignment itself. `stop_one` still calls `revoke_live` at `:751`, so a stop revokes every live grant of the session.
- The one writer at `:786` and its body are unchanged. `post_capability_grant`, `post_capability_deny`, `seed_grant`, `authorise`, `require_shell`, `grant_not_live`, `post_capability_request`, `get_capability_request`, `watch_ended`, `expire_due` and `seed_request` keep their bodies. No new request store, grant store, public method or reason string.

### Tests

Two tests in the module's `#[cfg(test)]`, passing with no operator and no probe build. They reuse `pending_request`, `granted_request`, `denied_request`, `grant_record`, `seed_shared_request`, `admit_shared`, `launch_finished`, `assert_capsule`, `assert_delete`, `assert_keys` and `request_entries`. Assertion text says the stand-in did the work.

- `standin_shell_revoke_drops_one_live_grant` at `standin-runtime/mod.rs:6102` admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice, finishes both starts, and reads `component-1` and `component-2` `running`. It seeds `req-1` and `req-3` on `component-1` and `req-2` on `component-2`, resource `localhost://Public/resident-instances/shared.txt`, action `read`, reason `read shared`, then `set_instant(4)`. Three shell grants are Ok `{"success":true}`: `req-1` `session` `grant shared read`, `req-3` `once` `grant once`, `req-2` `session` `grant sibling`. The shell live `request_id` set is exactly `req-1`, `req-2` and `req-3`. `authorise` for the `component-1` client and `req-1` is `Ok(())` and `grant_record` is `(Life::Live, false)`; `authorise` is not called for `req-3`. A shell `delete_capability` of `req-3` is Ok with only `success` and `revoked_request_id`. The `component-1` record set is `granted_request("req-1", "component-1", "grant shared read")` and `denied_request("req-3", "component-1", "Revoked by user")` with `settled_by` `shell`. `grant_record` for `req-3` is `(Life::Revoked, false)` and the live set is exactly `req-1` and `req-2`. `authorise` for the `component-1` client and `req-3` is 400 `grant is not live: Revoked`. `authorise` for `req-1` and for the `component-2` client's `req-2` are each `Ok(())`, and both records stay `(Life::Live, false)`. The `req-1` record stays granted with settler `shell`, and the `req-2` record stays granted with settler `shell` and decision reason `grant sibling`. Both instances stay `running` with cause `""`. A second `delete_capability` of `req-3` is 400 `Capability req-3 was not granted`, and the denied record, the `Revoked` grant and the `req-1`/`req-2` live set stay.
- `standin_shell_revoke_refuses_without_a_grant` at `:6345` starts from the same two running instances with `req-1` `Live` on `component-1`. A client `delete_capability` of `req-1` is 403 `This endpoint requires shell privileges`; the grant stays `(Life::Live, false)`, the record stays granted and both instances stay `running`. A shell delete of `missing` is 404 `Capability request not found: missing`. `req-p` is seeded on `component-1` and is not granted; a shell delete of `req-p` is 400 `Capability req-p was not granted`, and the record stays `pending_request("req-p", "component-1")`. The live set still holds `req-1`, and both instances stay `running` with cause `""`.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone and was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_drops_one_live_grant -- --exact`. Each planted crate compiled (`Compiling agent-conformance` then `Finished`), and each planted run exited 101 with that test failed on its assertion. After the last restore, the file's SHA-256 was `102fb14f75d85453f310739ec753563bcce2aae1255a3bb3a5754b9c04f96c15`, matching the pre-plant candidate, and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows the candidate only, with no plant.

F-standin-revoke-stub: the start of `delete_capability` returns Ok of `{"success": true, "revoked_request_id": "req-3"}` before the request store is read. Planted run failed at `standin-runtime/mod.rs:6226:9` (`:6225` restored): `assertion left == right failed: the stand-in did the work: the revoke denies req-3 and keeps req-1 granted`, `left: [Object {"action": String("read"), "decision_reason": String("grant shared read"), ...}, Object {"action": String("read"), "decision_reason": String("grant once"), "request_id": String("req-3"), ... "status": String("granted")}]`, `right: [... Object {"decision_reason": String("Revoked by user"), "request_id": String("req-3"), ... "status": String("denied")}]`.

Old:

```text
    pub fn delete_capability(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
```

New:

```text
    pub fn delete_capability(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "success": true, "revoked_request_id": "req-3" }));
        require_shell(caller)?;
```

F-standin-revoke-keep: the route writes the denied record and does not change that grant's life. Planted run failed at `standin-runtime/mod.rs:6237:9` (`:6238` restored): `assertion left == right failed: the stand-in did the work: the revoke drops the req-3 live grant`, `left: (Live, false)`, `right: (Revoked, false)`.

Old:

```text
            "shell",
        );
        self.revoke_grant(request_id);
        Ok(json!({
```

New:

```text
            "shell",
        );
        Ok(json!({
```

F-standin-revoke-session: the route calls `revoke_live` for `component-1`, so `req-1` becomes `Revoked` too. Planted run failed at `standin-runtime/mod.rs:6243:9` (same line restored): `assertion left == right failed: the stand-in did the work: it lists req-1 and req-2 after the revoke`, `left: {"req-2"}`, `right: {"req-1", "req-2"}`.

Old:

```text
        self.revoke_grant(request_id);
```

New:

```text
        self.revoke_live("component-1");
```

### Docs

`standin-runtime/README.md:59` adds one paragraph immediately before `## Callers` at `:61`: `delete_capability` answers `DELETE /api/capability/:id`; the id is the path segment; a client is 403 `This endpoint requires shell privileges` before the store is read; a missing record is 404 `Capability request not found: ` plus that id; a record that is not granted is 400 `Capability ` plus that id plus ` was not granted`; a shell revoke sets that granted record to `denied` with `decision_reason` `Revoked by user` and `settled_by` `shell`, and the one `Revoked` assignment then drops that live grant; the instance stays and another grant of that session stays; the Ok body's only keys are `success` and `revoked_request_id`, with no token; a stop still revokes every live grant of the session through `revoke_live`; a PASS gives the Runtime no A6 credit for this revoke. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph and the watch, survivor, expiry, once-grant, request-route, later-read and pending-cap paragraphs keep their bytes.

`RUNBOOK.md:743` adds one paragraph after the last stand-in paragraph: `standin_shell_revoke_drops_one_live_grant` is this stand-in, and a PASS there gives the Runtime no A6 credit for a shell revoke. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged, and the protected diff is empty: `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 251.04 seconds (user 53.49, sys 23.47), inside the 600-second bound. Observed targets: lib 64 passed 0 failed (a separate `--lib` run); report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. Cargo reached the last doc-tests target and printed no `error: test failed` line, so every earlier target passed. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.14 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_drops_one_live_grant -- --exact` exit 0, 1 passed and 0 failed, real 0.07 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The route takes one stored `request_id` at `standin-runtime/mod.rs:554` and adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The route removes authority: it drops one live grant at `:576` and mints none; no capsule, import or Home change, and the shell still holds no grant. |
| 3. A second path or a second copy of one rule? | No | `delete_capability` is the one route for `DELETE /api/capability/:id`; the one writer at `:570` stores the decision and `revoke_grant` at `:770` holds the one `Revoked` assignment, which `revoke_live` at `:757` also calls. No second writer, reason or assignment. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and its route, middleware and store are quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | A client is 403 `This endpoint requires shell privileges` at `:559`; a missing record is 404 at `:565`; a record that is not granted is 400 `Capability <id> was not granted` at `:567-569`; each writes nothing. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | No capsule code, world or import changes; the stand-in keeps the Runtime's one revoke decision, and the capsule keeps its own logic. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_shell_revoke_drops_one_live_grant` at `:6102` and `standin_shell_revoke_refuses_without_a_grant` at `:6345`; the stub, keep and session plants each fail the named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The shell check at `:559`, the record-status check at `:567` and the one grant-life write at `:576` are separate decisions; `revoke_grant` matches one id and one `Live` life at `:770-776`, and neither the instance phase nor another grant changes. |

A passing row gives the real Runtime no A6 credit for this revoke.

## 070 — A6: shell revoke-all drops every live grant

070: `post_capability_revoke_all` answers `POST /api/capability/revoke-all` on the same `StandIn`. It calls `require_shell` before it reads the body. It calls the one writer with `denied`, the shell reason and `shell` on every `Granted` record, then calls the one `Revoked` function for every `Live` grant. It does not call `revoke_live`, `delete_capability`, `settle_pending`, `post_capability_deny`, `post_capability_grant` or `authorise`. Every instance keeps its phase and cause, and a pending record and an `Exhausted` grant stay. The Ok value's only keys are `success` and `reason`, with no epoch. `standin_shell_revoke_all_drops_every_live_grant` and `standin_shell_revoke_all_refuses_without_shell` prove the route. `standin-runtime/README.md` states the route and its refusals, and `RUNBOOK.md` gains the matching row. A passing row gives the real Runtime no A6 credit.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md:318-320`, "Delegation and mandates":

```text
- **Allow once** authorizes one exact operation.
- **Allow for this session** authorizes a bounded operation set until the
  session ends or the grant is revoked.
```

This task takes the revoke half of the second sentence for every live grant at once: a session grant stops authorising while every instance keeps running. The one-grant revoke stays 069, and a standing mandate stays out.

### Quotes from the Runtime (read only, not imported)

`elastos/crates/elastos-server/src/api/server.rs:263-268` puts the route on the shell router:

```text
        .route("/api/capability/:id", delete(handlers::revoke_capability))
        .route(
            "/api/capability/revoke-all",
            post(handlers::revoke_all_capabilities),
        )
```

`elastos/crates/elastos-server/src/api/handlers/capability.rs:513-534` shows the body's only key, its default and the Ok keys:

```text
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAllInput {
    /// Reason for revoking all capabilities
    #[serde(default = "default_revoke_reason")]
    pub reason: String,
}

fn default_revoke_reason() -> String {
    "Revoked all by user".to_string()
}

#[derive(Debug, Serialize)]
pub struct RevokeAllOutput {
    pub success: bool,
    pub new_epoch: u64,
    pub reason: String,
}
```

`capability.rs:536-553` shows the handler and the epoch advance:

```text
/// POST /api/capability/revoke-all
///
/// Revoke all capabilities by advancing the epoch (shell only).
/// All tokens with epoch < new_epoch will be rejected.
pub async fn revoke_all_capabilities(
    State(state): State<CapabilityState>,
    Extension(_session): Extension<Session>, // Shell check done by middleware
    Json(input): Json<RevokeAllInput>,
) -> Json<RevokeAllOutput> {
    let new_epoch = state.capability_manager.revoke_all(&input.reason);

    // Mark all granted requests as revoked
    state.pending_store.revoke_all_granted().await;

    Json(RevokeAllOutput {
        success: true,
        new_epoch,
        reason: input.reason,
    })
}
```

`elastos/crates/elastos-server/src/api/middleware.rs:90-95` answers a client with status 403 and the reason `This endpoint requires shell privileges`. `elastos/crates/elastos-runtime/src/capability/pending.rs:544-566` sets every granted record to denied with the reason `Epoch advanced - all capabilities revoked`:

```text
    /// Mark all granted requests as revoked
    ///
    /// Called when epoch is advanced to revoke all capabilities
    pub async fn revoke_all_granted(&self) {
        let mut requests = self.requests.write().await;
        let now = SecureTimestamp::now();

        for (request_id, request) in requests.iter_mut() {
            if request.is_granted() {
                request.status = RequestStatus::Denied {
                    reason: "Epoch advanced - all capabilities revoked".to_string(),
                };
```

The stand-in copies the shell check, the body's one key, the default reason and the granted-record settlement. It does not copy the epoch, the token, `new_epoch` or the store's epoch reason.

### Code

- `post_capability_revoke_all` at `standin-runtime/mod.rs:590` is the only new public method. Its doc comment starts `POST /api/capability/revoke-all.` at `:583`. `require_shell(caller)?` at `:597` runs before the body is read at `:598`. `Value::Null` uses `Revoked all by user` at `:599`; an object reads its only key `reason` at `:600-615`; a body that is not an object and not null is 400 `revoke body needs an object` at `:617`; another key is 400 `revoke body rejects ` plus that key at `:605`; a non-string reason is 400 `revoke reason must be a string` at `:612-614`. Every refusal returns before a store write.
- On success the route collects the `Granted` request ids at `:620-624` and calls the one writer with `Denied`, the shell reason and `shell` for each at `:625-627`; it then collects the `Live` grant ids at `:629-633` and calls `revoke_grant` for each at `:634-636`. The Ok value at `:637` has only `success` and `reason`. It does not call `revoke_live`, `delete_capability`, `settle_pending`, `authorise`, `post_capability_grant` or `post_capability_deny`, and it adds no epoch counter.
- The one writer at `:843`, the one `Revoked` assignment at `:834`, `revoke_live` at `:814`, `delete_capability` at `:554`, `post_capability_grant` at `:470`, `post_capability_deny` at `:430`, `settle_pending` at `:865`, `stop_one` at `:794`, `seed_grant` at `:227`, `authorise` at `:659`, `require_shell` at `:1036`, `grant_not_live` at `:1135`, `post_capability_request`, `get_capability_request`, `watch_ended`, `expire_due` and `seed_request` keep their bodies. No new private function, no new field and no new reason string for the default beyond the one in the new method.

### Tests

Two tests in the module's `#[cfg(test)]`, passing with no operator and no probe build. They reuse `pending_request`, `granted_request`, `denied_request`, `grant_record`, `seed_shared_request`, `admit_shared`, `shared_body`, `launch_finished`, `assert_capsule`, `assert_delete`, `request_entries`, `request_ids` and `assert_live_request_ids_empty`. Assertion text says the stand-in did the work.

- `standin_shell_revoke_all_drops_every_live_grant` at `standin-runtime/mod.rs:6512` admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice, finishes both starts, and reads `component-1` and `component-2` `running`. It seeds `req-1` and `req-3` on `component-1` and `req-2` and `req-p` on `component-2`, resource `localhost://Public/resident-instances/shared.txt`, action `read`, reason `read shared`, then `set_instant(4)`. Three shell grants are Ok `{"success":true}`: `req-1` `session` `grant shared read`, `req-3` `once` `grant once`, `req-2` `session` `grant sibling`. `seed_grant` stores `req-orphan` on `component-2` (`res`, `read`, `session`, `granted_at` 4, `Live`, `session_ended` false). `authorise` for the `component-1` client and `req-3` is `Ok(())` and `grant_record` is `(Life::Exhausted, false)`. The shell live-grant `request_id` set is exactly `req-1`, `req-2` and `req-orphan`. A shell revoke-all of `{"reason":"stop every grant"}` is Ok `{"success":true,"reason":"stop every grant"}`. Both `component-1` records are denied with decision reason `stop every grant` and `settled_by` `shell`; `req-2` is denied the same way; `req-p` stays `pending_request("req-p", "component-2")`; the `component-2` record list has no `req-orphan`. `grant_record` is `(Life::Revoked, false)` for `req-1`, `req-2` and `req-orphan`, and `(Life::Exhausted, false)` for `req-3`. The shell live set is empty. `authorise` for `req-1` and `req-2` is 400 `grant is not live: Revoked`, and for `req-3` 400 `grant is not live: Exhausted`. Both instances stay `running` with cause `""`. A second revoke-all with the same body is the same Ok value and leaves those records, lives and the empty live set as they were.
- `standin_shell_revoke_all_refuses_without_shell` at `:6792` starts from the two running instances with `req-1` `Live` on `component-1` and `req-2` `Live` on `component-2`, both granted as in the first test. A client revoke-all of `{}` is 403 `This endpoint requires shell privileges`; a shell string body is 400 `revoke body needs an object`; `{"reason":"stop every grant","token":"req-1"}` is 400 `revoke body rejects token`; `{"reason":1}` is 400 `revoke reason must be a string`. After each refusal both grants stay `(Life::Live, false)` and both records stay granted. A shell `{}` is Ok `{"success":true,"reason":"Revoked all by user"}`, both records are denied with that reason and `settled_by` `shell`, both grants are `(Life::Revoked, false)`, the live set is empty, and both instances stay `running` with cause `""`.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone and was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_all_drops_every_live_grant -- --exact`. Each planted crate compiled (`Finished` `test` profile), and each planted run exited with that test failed on its assertion. After the last restore, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows the candidate only, with no plant; the file's SHA-256 is `5041b3a6294c63abb1fd74bd939f55fa69668ae976825d6b1a4b8528eac07d88`.

F-standin-revoke-all-stub: the start of `post_capability_revoke_all` returns Ok of `{"success": true, "reason": "stop every grant"}` before the caller is read. Planted run failed at `standin-runtime/mod.rs:6648:9` (`:6648` restored): `assertion left == right failed: the stand-in did the work: the revoke-all denies both component-1 records`, with the left records `granted` and the right records `denied`.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        const DEFAULT_REASON: &str = "Revoked all by user";

        require_shell(caller)?;
        let reason = match body {
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "success": true, "reason": "stop every grant" }));
        const DEFAULT_REASON: &str = "Revoked all by user";

        require_shell(caller)?;
        let reason = match body {
```

F-standin-revoke-all-keep: the route writes the denied records and does not call the `Revoked` function. Planted run failed at `standin-runtime/mod.rs:6669:9` (`:6679` restored): `assertion left == right failed: the stand-in did the work: the revoke-all drops the req-1 live grant`, `left: (Live, false)`, `right: (Revoked, false)`.

Old:

```text
        let live = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| grant.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        Ok(json!({ "success": true, "reason": reason }))
```

New:

```text
        Ok(json!({ "success": true, "reason": reason }))
```

F-standin-revoke-all-one-session: the route calls `revoke_live` for `component-1` and does not revoke `component-2`. Planted run failed at `standin-runtime/mod.rs:6675:9` (`:6684` restored): `assertion left == right failed: the stand-in did the work: the revoke-all drops the req-2 live grant`, `left: (Live, false)`, `right: (Revoked, false)`.

Old:

```text
        let live = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| grant.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        Ok(json!({ "success": true, "reason": reason }))
```

New:

```text
        self.revoke_live("component-1");
        Ok(json!({ "success": true, "reason": reason }))
```

### Docs

`standin-runtime/README.md:61` adds one paragraph immediately before `## Callers` at `:63`: `post_capability_revoke_all` answers `POST /api/capability/revoke-all`; a shell revoke sets every granted record to `denied` through the one writer with the shell reason and `settled_by` `shell`, and the one `Revoked` assignment then drops every live grant; the body's only key is a string `reason` and a missing reason is `Revoked all by user`; the instances stay, a pending record stays pending, and an exhausted grant stays `Exhausted`; the Ok body's only keys are `success` and `reason`, with no epoch; a stop still revokes one session through `revoke_live` and one grant still revokes through `delete_capability`; a PASS gives the Runtime no A6 credit for this revoke. The RA-1, RI-1 to RI-4 and settlement paragraphs keep their bytes, and so do the watch, survivor, expiry, once-grant, request-route, later-read, pending-cap and one-grant-revoke paragraphs.

`RUNBOOK.md:745` adds one paragraph after the last stand-in paragraph: `standin_shell_revoke_all_drops_every_live_grant` is this stand-in, and a PASS there gives the Runtime no A6 credit for a shell revoke of every grant. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged, and the protected diff is empty: `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The only changed files are `standin-runtime/mod.rs` (+493 lines), `standin-runtime/README.md` (+2) and `RUNBOOK.md` (+2), plus this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 252.23 seconds (user 54.04, sys 23.80), inside the 600-second bound. Observed targets: report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0 in both crates. Cargo reached the last doc-tests target and printed no `error: test failed` line, so every earlier target passed, including the agent-conformance lib target. A separate `-p agent-conformance --lib` run showed 66 passed and 0 failed, which is the previous 64 plus the two new tests. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.14 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_all_drops_every_live_grant -- --exact` passed 1 and failed 0 (65 filtered), real 0.06 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The route works on stored `request_id` values at `standin-runtime/mod.rs:620-636` and adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The route removes authority: it drops every live grant at `:629-636` and mints none; no capsule, import or Home change, and the shell still holds no grant. |
| 3. A second path or a second copy of one rule? | No | `post_capability_revoke_all` is the one route for `POST /api/capability/revoke-all`; it reuses the one writer at `:843` and the one `Revoked` assignment at `:834`, and it does not call `revoke_live` or `delete_capability`. No second writer, no second `Revoked` assignment and no second default reason. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and its route, middleware and store are quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | A client is 403 `This endpoint requires shell privileges` at `:597` before the body is read; a non-object body is 400 `revoke body needs an object` at `:617`; another key is 400 `revoke body rejects <key>` at `:605`; a non-string reason is 400 `revoke reason must be a string` at `:612-614`; each writes nothing. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | No capsule code, world or import changes; the stand-in keeps the Runtime's one revocation decision, and the capsule keeps its own logic. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_shell_revoke_all_drops_every_live_grant` at `:6512` and `standin_shell_revoke_all_refuses_without_shell` at `:6792`; the stub, keep and one-session plants each fail the named test on its assertion, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The shell check at `:597`, the record-status filter at `:620-624` and the grant-life filter at `:629-633` are separate decisions; the route changes no instance phase, and an `Exhausted` grant stays `Exhausted`. |

A passing row gives the real Runtime no A6 credit for this revoke.

### Round 2 — SPEC FIX extensions

The route's bytes stay as round 1 except its doc comment now states the refusal precedence: another body key is refused before a non-string `reason` is checked (`standin-runtime/mod.rs:588-589`). The two named tests now cover preserved record and grant states, a live grant with `session_ended: true`, all preserved grant fields, malformed client bodies, a null body, an empty reason, and the two-fault body precedence. All plants ran by hand and were restored before the next one.

`standin_shell_revoke_all_drops_every_live_grant` at `:6513` now seeds `req-expired` on `component-2`, lets it expire at instant 300, and then sets instant 4 through the existing `set_instant` seam. It seeds `req-denied` on `component-1` and denies it with the shell route before the revoke-all. It seeds `req-ended` on `component-2` (`res-ended`, `read`, `session`, `granted_at` 4, `Live`, `session_ended` true) and `req-old` on `component-1` (`res-old`, `read`, `session`, `granted_at` 4, `Expired`, `session_ended` false). The live-grant set before the revoke-all is exactly `req-1`, `req-2`, `req-ended` and `req-orphan`. After the revoke-all the component-1 records are `req-1` and `req-3` denied with `stop every grant` and `req-denied` still denied with `deny shared read`; the component-2 records are `req-2` denied with `stop every grant`, `req-expired` still expired, and `req-p` still pending. `req-ended` is `(Revoked, true)` and `req-old` is `(Expired, false)`. The `entry` view of `req-3`, `req-old` and `req-ended` keeps `request_id`, `session_id`, `resource`, `action`, `duration` and `granted_at`; `req-3` keeps its once duration and `req-ended` keeps `res-ended`. The second call leaves every record, every life and the empty live set.

`standin_shell_revoke_all_refuses_without_shell` at `:6937` now adds a client with a string body and a client with two body faults; both are 403 `This endpoint requires shell privileges` before the body is read. A shell body `{"reason":1,"token":"req-1"}` is 400 `revoke body rejects token`: the unknown key wins over the non-string reason. After the `{}` default-reason scenario it builds two fresh two-grant stand-ins. `Value::Null` is Ok `{"success":true,"reason":"Revoked all by user"}` and `{"reason":""}` is Ok `{"success":true,"reason":""}`; both records are denied with that shell reason, both grants are `(Revoked, false)`, the live set is empty and both instances stay `running`.

Hand-run plants: no `falsifiers.json` id and no new id. The drops-test command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_all_drops_every_live_grant -- --exact`. The refusal-test command was the same with `standin_runtime::tests::standin_shell_revoke_all_refuses_without_shell`. Each planted crate compiled and each planted run failed on its named assertion. After the last restore, `git diff` shows no plant.

F-standin-revoke-all-stub (drops): the start of `post_capability_revoke_all` returns Ok of `{"success": true, "reason": "stop every grant"}` before the caller is read. Failed at `:6690:9` on `:6696` ("the revoke-all denies both granted component-1 records and keeps req-denied"), with the left records `granted` and the right records `denied`.

Old:

```text
        const DEFAULT_REASON: &str = "Revoked all by user";

        require_shell(caller)?;
```

New:

```text
        const DEFAULT_REASON: &str = "Revoked all by user";

        return Ok(json!({ "success": true, "reason": "stop every grant" }));
        require_shell(caller)?;
```

F-standin-revoke-all-keep (drops): the route writes the denied records and does not call the `Revoked` function. Failed at `:6716:9` on `:6728` ("the revoke-all drops the req-1 live grant"), `left: (Live, false)`, `right: (Revoked, false)`.

Old:

```text
        let live = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| grant.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        Ok(json!({ "success": true, "reason": reason }))
```

New:

```text
        Ok(json!({ "success": true, "reason": reason }))
```

F-standin-revoke-all-one-session (drops): the route calls `revoke_live` for `component-1` and does not revoke `component-2`. Failed at `:6722:9` on `:6733` ("the revoke-all drops the req-2 live grant"), `left: (Live, false)`, `right: (Revoked, false)`.

Old:

```text
        let live = self
            .grants
            .iter()
            .filter(|grant| is_live(grant.life))
            .map(|grant| grant.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        Ok(json!({ "success": true, "reason": reason }))
```

New:

```text
        self.revoke_live("component-1");
        Ok(json!({ "success": true, "reason": reason }))
```

F-standin-revoke-all-overwrite-records (drops): the route settles every record, not only `Granted`. Failed at `:6689:9` on `:6696`; the left `req-denied` record reads `denied` with `stop every grant` and the right reads `denied` with `deny shared read`.

Old:

```text
            .filter(|request| request.status == RequestStatus::Granted)
```

New:

```text
            .filter(|_request| true)
```

F-standin-revoke-all-clear-ended (drops): the one `Revoked` function also clears `session_ended`. Failed at `:6746:9` on `:6748` ("the revoke-all drops the live grant and keeps its ended session flag"), `left: (Revoked, false)`, `right: (Revoked, true)`.

Old:

```text
            grant.life = Life::Revoked;
        }
    }
```

New:

```text
            grant.life = Life::Revoked;
            grant.session_ended = false;
        }
    }
```

F-standin-revoke-all-change-metadata (drops): the one `Revoked` function also clears `resource`. Failed at `:6796:13` on `:6798` ("the revoke-all keeps every field of req-ended"), with the left `resource` `""` and the right `res-ended`.

Old:

```text
            grant.life = Life::Revoked;
        }
    }
```

New:

```text
            grant.life = Life::Revoked;
            grant.resource = String::new();
        }
    }
```

F-standin-revoke-all-reject-null (refusal): a null body is refused as a non-object. Failed at `:7157:14` ("the stand-in accepts a null body as the default reason") with `(400, "revoke body needs an object")`.

Old:

```text
            Value::Null => DEFAULT_REASON,
```

New:

```text
            Value::Null => return Err((400, "revoke body needs an object".to_owned())),
```

F-standin-revoke-all-empty-default (refusal): an empty reason is replaced with the default reason. Failed at `:7209:9` on `:7212` ("an empty reason is stored as given"), `left` reason `Revoked all by user`, `right` reason `""`.

Old:

```text
                reason.unwrap_or(DEFAULT_REASON)
```

New:

```text
                reason.filter(|text| !text.is_empty()).unwrap_or(DEFAULT_REASON)
```

F-standin-revoke-all-change-default (refusal): the default reason loses ` by user`. Failed at `:7075:9` on `:7078` ("a missing reason is Revoked all by user"), `left` reason `Revoked all`, `right` reason `Revoked all by user`.

Old:

```text
        const DEFAULT_REASON: &str = "Revoked all by user";
```

New:

```text
        const DEFAULT_REASON: &str = "Revoked all";
```

F-standin-revoke-all-shell-after-body (refusal): `require_shell` moves after the body parse. Failed at `:1768:9` on the helper assertion for `:7031` ("a client with a malformed body is refused before the body is read"), with `Err((400, "revoke body needs an object"))`.

Old:

```text
        require_shell(caller)?;
        let reason = match body {
```

New:

```text
        let reason = match body {
```

and:

Old:

```text
            _ => return Err((400, "revoke body needs an object".to_owned())),
        };
        let granted = self
```

New:

```text
            _ => return Err((400, "revoke body needs an object".to_owned())),
        };
        require_shell(caller)?;
        let granted = self
```

F-standin-revoke-all-accept-extra-key (refusal): the unknown-key guard is removed. Failed at `:1765:9` on the helper assertion for `:7011` ("another body key is refused"), with `Ok({"reason":"req-1","success":true})`.

Old:

```text
                for (key, value) in object {
                    if key != "reason" {
                        return Err((400, format!("revoke body rejects {key}")));
                    }
                    match value {
```

New:

```text
                for (_key, value) in object {
                    match value {
```

F-standin-revoke-all-accept-non-object (refusal): a non-object body uses the default reason. Failed at `:1768:9` on the helper assertion for `:7001` ("a string body is refused"), with `Ok({"reason":"Revoked all by user","success":true})`.

Old:

```text
            _ => return Err((400, "revoke body needs an object".to_owned())),
```

New:

```text
            _ => DEFAULT_REASON,
```

F-standin-revoke-all-reverse-precedence (refusal): a non-string reason returns before the unknown-key check. Failed at `:1768:9` on the helper assertion for `:7051` ("an unknown body key wins over a non-string reason"), with `Err((400, "revoke reason must be a string"))`.

Old:

```text
                        Value::String(text) => reason = Some(text.as_str()),
                        _ => reason_not_string = true,
```

New:

```text
                        Value::String(text) => reason = Some(text.as_str()),
                        _ => return Err((400, "revoke reason must be a string".to_owned())),
```

F-standin-revoke-all-drop-reason-guard (refusal): the non-string reason guard is removed. Failed at `:1765:9` on the helper assertion for `:7019` ("a non-string reason is refused"), with `Ok({"reason":"Revoked all by user","success":true})`.

Old:

```text
                if reason_not_string {
                    return Err((400, "revoke reason must be a string".to_owned()));
                }
                reason.unwrap_or(DEFAULT_REASON)
```

New:

```text
                reason.unwrap_or(DEFAULT_REASON)
```

After the last restore, the two named tests pass and `git diff --stat` shows only `standin-runtime/mod.rs` as changed.

### Round 2 gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. No `Cargo.toml` or `Cargo.lock` change. `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The production method differs from round 1 only by its two doc lines; no plant remains.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.13 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: real 246.26 seconds, inside the 600-second bound. Observed: lib 66 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0 in both crates. No census line and no listed flaky test failed, so the rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0 in 0.13 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_revoke_all_drops_every_live_grant -- --exact` passed 1, failed 0 (65 filtered) in 0.06 seconds.
- `git diff --stat`: `LOG.md` and `standin-runtime/mod.rs` only. Restored `standin-runtime/mod.rs` SHA-256: `c11c848fe5e4ecf02428b15888b7e67151e47920f0510c8238d06c56e003f617`.

The eight principle answers above still hold. Row 3 gains no second path or rule: the refusals stay in the one method and the revoke stays on the one writer and the one `Revoked` assignment. Row 5 covers the null body, the empty reason, the malformed client body and the two-fault precedence. Row 7 now names fourteen caught plants, six on the drops test and eight on the refusal test.

070 round 2: extended both revoke-all tests to preserved denied and expired records, an expired grant, a live grant with `session_ended: true`, all preserved grant fields, malformed client bodies, a null body, an empty reason and the two-fault refusal precedence; the route gained only its precedence doc sentence, and fourteen hand-run plants each failed the named test.

### 070 repair — failure owns session cleanup

The failure transitions in `post_capability_deny` and `finish_start` now use
`revoke_live` and `settle_pending`. The shared cleanup revokes the failed
session's live grants and settles its remaining pending requests with the
failure cause. The shell keeps ownership of the explicit deny record; runtime
owns the other settlements. The sibling session keeps its records and grants.
`post_capability_grant`, `authorise`, the request writer and the grant writers
keep their existing rules.

`standin_failure_ends_session_authority` submits requests through the public
request method before start returns. It covers shell denial with `Start::Ok`,
`Start::Error` and `Start::Trap`. Each case proves that session and once grants
return `grant is not live: Revoked`, a grant of the third request returns
`request is not pending: request-3`, and the sibling still has authority.
Before the repair, this test failed at `mod.rs:3509` because the first grant
still returned `Ok(())` (exit 101, 2.91 seconds). The existing shell-deny test
now checks the runtime settlement of `req-extra`, its exact repeat-deny
refusal, and preservation of the failure cause on a later seeded request.

The revoke-all test uses one metadata assertion for all six grants: `req-1`,
`req-2`, `req-orphan`, `req-3`, `req-old` and `req-ended`. It runs after each
revoke-all call and compares `request_id`, `session_id`, `resource`, `action`,
`duration` and `granted_at`. The existing life and `session_ended` assertions
also run after each call.

#### Repair plants

All five plants compiled and failed on their test assertions. Each plant was
restored byte for byte before the next. The commands used
`CARGO_BUILD_BUILD_DIR=$PWD/lab/agent-conformance/target/host-build`,
`CARGO_TARGET_DIR=$PWD/lab/agent-conformance/target`, `CARGO_INCREMENTAL=0`
and `RUST_TEST_THREADS=2`. The test command was
`cargo test --offline --locked --manifest-path lab/agent-conformance/Cargo.toml --lib TEST -- --exact`.
The first two plants below use
`standin_runtime::tests::standin_shell_revoke_all_drops_every_live_grant`.
The other three use
`standin_runtime::tests::standin_failure_ends_session_authority`.

F-standin-revoke-all-overwrite-expired-grant specifically overwrites the
`Expired` grant. This is separate from the earlier overwrite-records plant,
which exercises request status. Exit 101 in 8.03 seconds at the planted
`mod.rs:6904`: `the stand-in did the work: the revoke-all leaves the expired req-old grant`;
actual `(Revoked, false)`, expected `(Expired, false)`. Restored, the exact
test passed in 1.76 seconds.

Old bytes:

```text
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        Ok(json!({ "success": true, "reason": reason }))
```

New bytes:

```text
        for request_id in live {
            self.revoke_grant(&request_id);
        }
        for grant in &mut self.grants {
            if grant.life == Life::Expired {
                grant.life = Life::Revoked;
            }
        }
        Ok(json!({ "success": true, "reason": reason }))
```

F-second-revoke-change-orphan-metadata changes `req-orphan` only on the second
call. Exit 101 in 1.54 seconds at the planted `mod.rs:6983`:
`the stand-in did the work: the revoke-all keeps every field of req-orphan`;
actual resource `""`, expected `"res"`.

Old bytes:

```text
        let granted = self
```

New bytes:

```text
        if self.grants.iter().all(|grant| !is_live(grant.life)) {
            if let Some(grant) = self.grants.iter_mut().find(|grant| grant.request_id == "req-orphan") {
                grant.resource.clear();
            }
        }
        let granted = self
```

F-deny-keep-grants removes the following complete line, including its newline,
from `post_capability_deny` (new bytes are empty). Exit 101 in 2.06 seconds at
the planted `mod.rs:3533`: `shell denied start revokes the session and once grants`;
actual `Ok(())`, expected `Err((400, "grant is not live: Revoked"))`.

```text
                self.revoke_live(&session_id);
```

F-deny-keep-pending removes the following complete line, including its newline,
from `post_capability_deny` (new bytes are empty). Exit 101 in 1.39 seconds at
the planted `mod.rs:3544`: `failure settles the third request before a later grant`;
actual success, expected `Err((400, "request is not pending: request-3"))`.

```text
                self.settle_pending(&session_id, reason);
```

F-failed-start-keep-grants removes revocation from `finish_start`. Exit 101
in 1.34 seconds at the planted `mod.rs:3533`:
`start refused revokes the session and once grants`; actual `Ok(())`, expected
`Err((400, "grant is not live: Revoked"))`.

Old bytes:

```text
        let cause = instance.cause.clone();
        self.revoke_live(&session_id);
```

New bytes:

```text
        let cause = instance.cause.clone();
```

#### Restored repair checks

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`:
  exit 0 in 0.16 seconds.
- With the environment above,
  `cargo test --offline --locked --manifest-path lab/agent-conformance/Cargo.toml --lib --test standin_contract`:
  exit 0 in 6.89 seconds; 67 stand-in tests, two contract tests and three probe
  unit tests passed. These checks use the stand-in without an operator or a
  probe artifact build.
- Restored `standin-runtime/mod.rs` SHA-256:
  `f402f7f2ab88963bf0abdae6e3fe9532695061e221f960e29158971c07688ae2`.
  Only that source file and this log changed in this repair. Cargo manifests,
  lockfile, falsifier registry and the other lane sources keep their bytes.
- The supervisor owns the full gate and fresh review. This repair used the
  bounded checks above; the full suite includes Git identity checks, and this
  turn's instructions prohibit running Git.

## 071 — A11: the store holds at most 1024 pending requests

071: `standin-runtime/mod.rs` gains one constant, `MAX_PENDING_REQUESTS: usize = 1024` at `:36`, beside `MAX_PENDING_PER_SESSION: usize = 32` at `:37`. `seed_request` at `:257` counts every `Pending` record in the store at `:282-286`, after the empty-field refusal and the duplicate-id refusal, and before the per-session count at `:290-296` and the push at `:300`. At 1024 the call returns `Err((400, "Too many pending requests"))` at `:287-289` and pushes nothing. This check removes no record, so a `Granted`, `Denied` or `Expired` record stays for the 60-second read and does not count. `post_capability_request` at `:342` is unchanged: `self.seed_request(...)?` at `:382` returns the same status and reason, and `next_request += 1` at `:383` runs only after `Ok`. The route counts nothing. One store, one counter, one reason string.

### Quote from the Runtime store (read only, `elastos/crates/elastos-runtime/src/capability/pending.rs`)

The constant at `:20`:

> ```rust
> pub const MAX_PENDING_REQUESTS: usize = 1024;
> ```

The capacity block in `create_request_with_reason` counts every stored record at `:258-265`, and at that limit it runs `cleanup_expired` then `cleanup_old(0)` before it looks again:

> ```rust
>         // Capacity guard: evict expired if at limit
>         {
>             let count = self.requests.read().await.len();
>             if count >= MAX_PENDING_REQUESTS {
>                 self.cleanup_expired().await;
>                 self.cleanup_old(0).await;
>             }
>         }
> ```

`cleanup_old(0)` removes resolved records and keeps pending ones. When 1024 pending records remain, the next request is not inserted, and the reason is `Too many pending requests` at `:266-282`:

> ```rust
>         // Re-check after cleanup — reject if still at capacity
>         {
>             let count = self.requests.read().await.len();
>             if count >= MAX_PENDING_REQUESTS {
>                 let mut request = PendingCapabilityRequest::new_with_reason(
>                     session_id.clone(),
>                     resource.clone(),
>                     action,
>                     reason.clone(),
>                     self.timeout_secs,
>                 );
>                 request.status = RequestStatus::Denied {
>                     reason: "Too many pending requests".to_string(),
>                 };
>                 return request;
>             }
>         }
> ```

### Quote from the handler (read only, `elastos/crates/elastos-server/src/api/handlers/capability.rs`)

A denied object from the store becomes status `denied` with that same reason and a `request_id`, and the object was not inserted. `request_capability` does that at `:127-135`:

> ```rust
>     // If pre-denied (e.g. rate limit), surface the denial immediately
>     if request.is_denied() {
>         return Ok(Json(RequestCapabilityOutput {
>             status: "denied".to_string(),
>             request_id: Some(request.id.to_string()),
>             token: None,
>             reason: Some("Too many pending requests".to_string()),
>         }));
>     }
> ```

The stand-in does not copy the unstored denied object or that `request_id`; its `seed_request` returns the 400 and pushes nothing. The per-session cap already returns status 400 from `seed_request`, and the store-wide cap uses that same shape.

### Quote from the contract (read only, `docs/AGENT_ARCHITECTURE.md`, "Request flow", step 8 at `:235-236`)

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

One session's cap of 32 stays the session reason. This task is the store.

### Tests

One test in `standin_runtime::tests`, passing with no operator and no probe build. It reuses `launch_two_running`, `request_entries` and `expired_request`, and adds one local helper `pending_count` at `:1899` that counts records whose status word is `pending` across every session. Every assertion says the stand-in did the work.

- `standin_store_holds_at_most_1024_pending` (`:6092`) admits `/capsules/read-shared` as `read-shared` with `Start::Ok`, launches twice and finishes both starts, so `component-1` and `component-2` are `running`. `seed_request` of `old` on `s-old` with `SHARED_RESOURCE`, action `read` and reason `read shared` is stored at instant 0; `set_instant(300)` makes `request_entries` for `s-old` equal `vec![expired_request("old", "s-old")]`. `pack-1` through `pack-32` on session `packed` with resource `res`, action `read` and reason `bulk` are Ok. `pack-33` on `packed` is status 400 with `Too many pending requests for this session`, and no `pack-33` is stored. `fill-1` through `fill-992` on sessions `f-1` through `f-992` with that same resource, action and reason are Ok. The pending count is 1024, and `old` stays expired. `over` on `s-over` is status 400 with `Too many pending requests`, and no `over` is stored. `pack-34` on `packed` is that same global reason, not the session reason, and no `pack-34` is stored. `post_capability_grant` as the shell with `{"request_id":"fill-1","duration":"session","rationale":"grant one"}` is Ok `{"success": true}`, and the shell record for `fill-1` is granted with `decision_reason` `grant one` and `settled_by` `shell`. `room` on `s-room` is Ok, and the pending count is 1024 again. `post_capability_request` for the `component-2` client with the shared read body is status 400 with `Too many pending requests`, and no `request-1` is stored. `post_capability_deny` as the shell with `{"request_id":"room","reason":"deny room"}` is Ok `{"success": true}`. The same client call is then Ok `{"status":"pending","request_id":"request-1"}`, and the pending count is 1024. A further client call is status 400 with the same global reason, no `request-2` is stored, and `request-1` stays pending. Both instances stay `running` with cause `""`.

### Hand-run falsifiers

Each plant ran alone and was restored before the next. The command was `env RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_store_holds_at_most_1024_pending -- --exact`. The planted crate compiled every time, and every planted run exited 101. After the last restore, `sha256sum standin-runtime/mod.rs` was `e4ff9689eeac33e8e608b945c074691997b4e76d9d8039a7f96d7bc4bffe013f`, equal to the candidate hash before the first plant, and `git diff -- lab/agent-conformance/standin-runtime/mod.rs` showed the candidate only. No `falsifiers.json` id was added.

F-standin-store-stub. Assertion: planted `mod.rs:6140:9` `assertion \`left == right\` failed: the stand-in did the work: over is refused while the store holds 1024 pending records`, `left: Ok(())`, `right: Err((400, "Too many pending requests"))`.

Old:

```text
            return Err((400, format!("request already stored: {request_id}")));
        }
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
        if pending_in_store >= MAX_PENDING_REQUESTS {
            return Err((400, "Too many pending requests".to_owned()));
        }
        let pending = self
```

New:

```text
            return Err((400, format!("request already stored: {request_id}")));
        }
        let pending = self
```

F-standin-store-settled. Assertion: planted `mod.rs:6140:18` `the stand-in stores the fill pending record: (400, "Too many pending requests")`, so the 1024 `fill` and `pack` records do not all store while `old` remains.

Old:

```text
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
```

New:

```text
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| {
                matches!(
                    request.status,
                    RequestStatus::Pending | RequestStatus::Expired
                )
            })
            .count();
```

F-standin-store-session. Assertion: planted `mod.rs:6150:9` `assertion \`left == right\` failed: the stand-in did the work: over is refused while the store holds 1024 pending records`, `left: Ok(())`, `right: Err((400, "Too many pending requests"))`.

Old:

```text
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .count();
```

New:

```text
        let pending_in_store = self
            .requests
            .iter()
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .count();
```

### Docs

`standin-runtime/README.md:63` adds one paragraph immediately before `## Callers`: `seed_request` holds at most 1024 pending records in the store; the next one is status 400 with `Too many pending requests` and stores nothing; a granted, denied or expired record does not count and the check does not remove it; the per-session cap of 32 stays and is the reason when the store holds fewer than 1024 pending records; at 1024 the store reason wins; `post_capability_request` returns that status and reason and counts nothing; a PASS gives the Runtime no A11 credit for this cap. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph and the watch, survivor, expiry, once-grant, request-route, later-read, pending-cap and revoke paragraphs keep their bytes. `RUNBOOK.md:747` adds one paragraph after the last stand-in paragraph: `standin_store_holds_at_most_1024_pending` is this stand-in, and a PASS there gives the Runtime no A11 credit for the store cap. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged; `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 249.07 seconds (4m09.07s), inside the 600-second bound. Targets in order: lib 68 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply. An earlier full run finished in 251.94 seconds but its output was cut by a tail, so it is not the recorded result.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.14 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_store_holds_at_most_1024_pending -- --exact` exit 0, 1 passed and 0 failed, real 0.11 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The cap counts stored `request_id` records at `standin-runtime/mod.rs:282-286` and adds no code or content identity. |
| 2. Capsule, Home or UI gains ungranted access? | No | The cap only refuses a pending record at `:287-289`; it mints no grant, token or resource access, and Home holds nothing new. |
| 3. A second path or a second copy of one rule? | No | The one store count lives in `seed_request` at `:282-286`, and `post_capability_request` reaches it through `self.seed_request(...)?` at `:382`; no other method counts store-wide pending records. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and its store is quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | The pending record after 1024 returns 400 `Too many pending requests` at `:287-289` and pushes nothing at `:300`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The change stores or refuses one record in the stand-in's request store; no capsule code, import or world changes. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_store_holds_at_most_1024_pending` at `:6092`; the stub, settled-record and caller-session plants each fail that test, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The store count matches no identity claim, the phase gate at `:372-380` stays separate, and a shell grant frees a slot without minting allowance by itself. |

A passing row gives the real Runtime no A11 credit for this cap.

### Round 2 — supervisor cleanup-census failure and passing rerun

The supervisor reran `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` and got exit 101. The effects target reported 60 passed, 1 failed and 12 ignored in 179.91 seconds. The only failure was `attach_secret_stays_in_memory` at `tests/effects.rs:497:5`, with:

```text
cleanup census: FAIL retained:target/home-11385-1793172242010424000-11; process leftover; processes:1 paths:["home/Library/Application Support/elastos/host-process.lock"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)
```

That row, `tests/effects.rs`, `src/census.rs` and the fixture operator are outside this task's paths, and this candidate adds no process, no fixture Home and no census change. The failure is the intermittent cleanup-census class already recorded under 029; its cause stays unproven. No test, census, operator or reason was changed to make it pass, and the candidate source keeps its bytes.

The required gate was rerun on the unchanged candidate with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 298.04 seconds, inside the 600-second bound. Targets in order: lib 68 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed.
- `standin-runtime/mod.rs` SHA-256 stays `e4ff9689eeac33e8e608b945c074691997b4e76d9d8039a7f96d7bc4bffe013f`; only this log changed in round 2.

## 074 — A6: system and wallet requests never become pending

074: `post_capability_request` calls one private function, `prestore_denial(resource, action)`, after the live-instance refusal and before the request id is minted. `Some` returns Ok `{"status":"denied","reason":...}` and stores nothing; `None` falls through to the existing `seed_request` success. The system compare runs before the wallet compare. The segment is the text after `elastos://` before the first `/`, `?` or `#`, compared case-sensitively, and `action` is the lowercased action the route already validated. The shell, body, scheme, action, unknown-instance and `not_live` refusals keep their order, status and text. `seed_request` is still the only writer and keeps its body, including the 071 store-wide count. `standin_system_and_wallet_requests_never_become_pending` fails on each of the twelve hand-run plants and passes when they are restored.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md:233-236`, "Request flow", steps 7 and 8:

```text
7. Runtime verifies the exact resource, action, operation, principal, session,
   capsule, grant, expiry, and revocation state.
8. If additional consent is required, Runtime records a pending request and
   Home or Inbox presents it. The UI does not mint the grant itself.
```

This task is the gate in step 7 for the two resources the Runtime denies before the store in step 8. A standing mandate stays out.

### Quotes from the Runtime (read only, not imported)

`elastos/crates/elastos-server/src/api/handlers/capability.rs:90-115` shows the scheme refusal and the two `Ok` branches after the action check, before `create_request_with_reason` at `:122-125`:

```text
    if !is_supported_resource_scheme(&input.resource) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported resource scheme. Allowed: elastos://, localhost://".to_string(),
        ));
    }

    if is_system_only_backend_resource(&input.resource) {
        return Ok(Json(RequestCapabilityOutput {
            status: "denied".to_string(),
            request_id: None,
            token: None,
            reason: Some(
                "system backends are not app capabilities; use elastos://content".to_string(),
            ),
        }));
    }

    if let Err(reason) = ensure_generic_wallet_capability(&input.resource, action) {
        return Ok(Json(RequestCapabilityOutput {
            status: "denied".to_string(),
            request_id: None,
            token: None,
            reason: Some(reason),
        }));
    }
```

`elastos/crates/elastos-common/src/localhost.rs:36-53` names the seven first segments and the split set:

```text
pub fn is_system_only_backend_resource(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("elastos://") else {
        return false;
    };

    matches!(
        rest.split(['/', '?', '#']).next(),
        Some(
            "elacity"
                | "elacity-sdk"
                | "gateway"
                | "ipfs"
                | "ipfs-cluster"
                | "ipfs-provider"
                | "kubo"
        )
    )
}
```

`elastos/crates/elastos-server/src/provider_resource.rs:12` and `:577-594` give the exact status resource, the wallet segment rule and the wallet reason:

```text
pub const WALLET_STATUS_RESOURCE: &str = "elastos://wallet/meta/status";
```

```text
pub fn is_wallet_resource(resource: &str) -> bool {
    resource
        .strip_prefix("elastos://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        == Some("wallet")
}

pub fn ensure_generic_wallet_capability(resource: &str, action: Action) -> Result<(), String> {
    if !is_wallet_resource(resource)
        || (resource == WALLET_STATUS_RESOURCE && action == Action::Read)
    {
        return Ok(());
    }
    Err(
        "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations"
            .to_string(),
    )
}
```

The system reason is `system backends are not app capabilities; use elastos://content`. The wallet reason is `generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations`. The seven first-segment names are `elacity`, `elacity-sdk`, `gateway`, `ipfs`, `ipfs-cluster`, `ipfs-provider` and `kubo`. The exact status resource is `elastos://wallet/meta/status`, and only action `read` passes it.

### Code

- `prestore_denial` at `standin-runtime/mod.rs:1332` is the only new private production function. It strips `elastos://`, takes the first `split(['/', '?', '#'])` segment without lowercasing it, then compares the seven system names at `:1340-1345` before the wallet segment at `:1346-1348`. The status resource and action `read` are its one exception. The two reasons are the only copies of their text in the module.
- `post_capability_request` calls it once at `:383`, after the live-instance refusal at `:380-382` and before `format!("request-{}", self.next_request)` at `:386`. `Some` returns the denied Ok object at `:384` with only `status` and `reason`; nothing is stored and `next_request` stays. `None` reaches the unchanged `self.seed_request(...)?` at `:387`, which is still the only writer. The doc comment at `:341-342` names the new denial.
- `seed_request` at `:257` keeps its full body, including the 1024 store-wide count. `get_capability_requests`, `post_capability_grant`, `post_capability_deny`, `delete_capability`, `post_capability_revoke_all` and `authorise` keep their bodies; `authorise` has no resource or action parameter, so 072 has not landed here. No new public method, no second denial function and no second name list.

### Tests

`standin_system_and_wallet_requests_never_become_pending` at `standin-runtime/mod.rs:7679` in the module's `#[cfg(test)]`, passing with no operator and no probe build. It reuses `launch_two_running`, `request_entries`, `pending_request`, `launch_starting`, `assert_capsule`, `assert_live_request_ids_empty` and `stop_body`. It compares each complete denied object, so each exact reason and the absence of `request_id`, `token` and `error` are asserted. It uses independent reason literals. Assertion text says the stand-in did the work.

- Two running instances `component-1` and `component-2`. For the `component-1` client, ten system bodies are each Ok `{"status":"denied","reason":"system backends are not app capabilities; use elastos://content"}`: `elastos://elacity/x`, `elastos://elacity-sdk/x`, `elastos://gateway/x`, `elastos://ipfs/x`, `elastos://ipfs-cluster/x`, `elastos://ipfs-provider/x`, `elastos://kubo/x`, `elastos://ipfs?hash`, the bare `elastos://ipfs` and `elastos://kubo#x`, each with action `read` and reason `read shared`.
- Six wallet bodies are each Ok `{"status":"denied","reason":"generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations"}`: `elastos://wallet/open` with `read`, `elastos://wallet/meta/status` with `write`, `elastos://wallet/meta/status/extra` with `read`, the bare `elastos://wallet`, `elastos://wallet?open` and `elastos://wallet#open` with `read`.
- Both `request_entries` lists are empty after those sixteen denials. `elastos://IPFS/x` stores `request-1`, `elastos://wallet/meta/status` with `read` stores `request-2` and `elastos://content/demo` stores `request-3`. The three shell records equal `pending_request` bases with the three resources, so every field, including action `read`, is compared. A further `elastos://gateway/meta` body is denied, stores nothing and leaves `next_request` at 4, so no `request-4` is minted.
- A shell stop of `component-2` with `{"reason":"stop one"}` then makes `elastos://ipfs/x` from that client 400 `instance is not live: stopped`; its records stay empty, `component-1` stays `running` with cause `""`, and the shell live-grant `request_id` set is empty.
- A third launch `component-3` stays `starting`; one system and one wallet denial on it are each the full denied object, its records stay empty, it stays `starting`, and `next_request` stays at 4.
- A second `StandIn` shows the near misses store: `elastos://ipfs-extra/x` is `request-1` and `elastos://elacity-sdk-extra/x` is `request-2`, so matching is by whole segment; `elastos://wallet/meta/status` with action `Read` is `request-3`, so the exception reads the lowercased action; `elastos://Wallet/open` is `request-4`, so the wallet segment keeps its case.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone, the planted crate compiled, and it was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_system_and_wallet_requests_never_become_pending -- --exact`. Every planted run exited 101 with that test failed on its assertion. After the last restore, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows the candidate only, with no plant; `standin-runtime/mod.rs` SHA-256 is `3c45124d1fad7970fcb388d0588eaa34f9c8f4a515dce4201acce6186fe774fb` before and after the plants.

F-standin-prestore-stub: the call is removed, so `elastos://ipfs/x` is stored. Planted run failed at `mod.rs:7721:13` (`:7724` restored): `assertion left == right failed: the stand-in did the work: it denies elastos://elacity/x before the store`, `left: Ok({"request_id":"request-1","status":"pending"})`, `right: Ok({"reason":"system backends are not app capabilities; use elastos://content","status":"denied"})`.

Old:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
```

New:

```text
```

F-standin-prestore-keep: the route returns the denied body and still calls `seed_request` for that resource. Planted run failed at `mod.rs:7757:9` (`:7754` restored): `the stand-in did the work: the denied requests store nothing for component-1`.

Old:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
```

New:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            let stored_id = format!("request-{}", self.next_request);
            self.seed_request(&stored_id, session_id, resource, &action, reason)?;
            self.next_request += 1;
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
```

F-standin-prestore-wallet: `elastos://wallet/meta/status` with action `read` takes the wallet reason. Planted run failed at `mod.rs:7784:9`: `assertion left == right failed: the stand-in did the work: the read-only status resource stores request-2`, `left` the denied wallet reason, `right: Ok({"request_id":"request-2","status":"pending"})`.

Old:

```text
    if segment == "wallet" && !(resource == "elastos://wallet/meta/status" && action == "read") {
```

New:

```text
    if segment == "wallet" {
```

F-standin-prestore-wallet-bypass: system denials keep working and every wallet resource becomes pending. Planted run failed at `mod.rs:7747:13`: `assertion left == right failed: the stand-in did the work: it denies elastos://wallet/open with action read before the store`, `left: Ok({"request_id":"request-1","status":"pending"})`, `right` the denied wallet reason.

Old:

```text
        return Some(WALLET_REASON);
```

New:

```text
        return None;
```

F-standin-prestore-running-only: the gate applies only to a `running` instance. Planted run failed at `mod.rs:7900:13` (`:7898` restored): `assertion left == right failed: the stand-in did the work: it denies elastos://ipfs/x from a starting instance`, `left: Ok({"request_id":"request-4","status":"pending"})`, `right` the denied system reason.

Old:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
```

New:

```text
        if matches!(phase, ResidentStatus::Running) {
            if let Some(reason) = prestore_denial(resource, &action) {
                return Ok(json!({ "status": "denied", "reason": reason }));
            }
        }
```

F-standin-prestore-action: the route passes the original action, so the status exception misses `Read`. Planted run failed at `mod.rs:7959:13`: `assertion left == right failed: the stand-in did the work: the status exception reads the lowercased action and stores request-3`, `left` the denied wallet reason, `right: Ok({"request_id":"request-3","status":"pending"})`.

Old:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
```

New:

```text
        if let Some(reason) = prestore_denial(resource, given_action) {
```

F-standin-prestore-system-reason: the system reason text changes. Planted run failed at `mod.rs:7725:13` (`:7724` restored): `the stand-in did the work: it denies elastos://elacity/x before the store`, `left` the reason with ` now`, `right` the exact reason.

Old:

```text
    const SYSTEM_REASON: &str = "system backends are not app capabilities; use elastos://content";
```

New:

```text
    const SYSTEM_REASON: &str =
        "system backends are not app capabilities; use elastos://content now";
```

F-standin-prestore-wallet-reason: the wallet reason text changes. Planted run failed at `mod.rs:7747:13`: `the stand-in did the work: it denies elastos://wallet/open with action read before the store`, `left` the reason with ` now`, `right` the exact reason.

Old:

```text
    const WALLET_REASON: &str = "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations";
```

New:

```text
    const WALLET_REASON: &str = "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations now";
```

F-standin-prestore-extra-key: the denied Ok object gains `request_id`. Planted run failed at `mod.rs:7729:13` (`:7724` restored): `left: Ok({"reason":"system backends are not app capabilities; use elastos://content","request_id":"request-1","status":"denied"})`, `right` the two-key object.

Old:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            return Ok(json!({ "status": "denied", "reason": reason }));
        }
```

New:

```text
        if let Some(reason) = prestore_denial(resource, &action) {
            let denied_id = format!("request-{}", self.next_request);
            return Ok(json!({
                "status": "denied",
                "reason": reason,
                "request_id": denied_id,
            }));
        }
```

F-standin-prestore-separators: the segment splits on `/` only. Planted run failed at `mod.rs:7721:13` (`:7724` restored): `the stand-in did the work: it denies elastos://ipfs?hash before the store`, `left: Ok({"request_id":"request-1","status":"pending"})`, `right` the denied system reason.

Old:

```text
    let segment = resource
        .strip_prefix("elastos://")?
        .split(['/', '?', '#'])
        .next()?;
```

New:

```text
    let segment = resource.strip_prefix("elastos://")?.split('/').next()?;
```

F-standin-prestore-prefix: the system compare matches a prefix, so `ipfs-extra` is denied. Planted run failed at `mod.rs:7967:13` (`:7959` restored): `the stand-in did the work: ipfs-extra is not the ipfs segment and stores request-1`, `left` the denied system reason, `right: Ok({"request_id":"request-1","status":"pending"})`.

Old:

```text
    if matches!(
        segment,
        "elacity" | "elacity-sdk" | "gateway" | "ipfs" | "ipfs-cluster" | "ipfs-provider" | "kubo"
    ) {
        return Some(SYSTEM_REASON);
    }
```

New:

```text
    if [
        "elacity",
        "elacity-sdk",
        "gateway",
        "ipfs",
        "ipfs-cluster",
        "ipfs-provider",
        "kubo",
    ]
    .iter()
    .any(|name| segment.starts_with(name))
    {
        return Some(SYSTEM_REASON);
    }
```

F-standin-prestore-lowercase: the segment is lowercased, so `IPFS` is denied. Planted run failed at `mod.rs:7773:9` (`:7771` restored): `assertion left == right failed: the stand-in did the work: the segment compare keeps its case, so IPFS stores request-1`, `left` the denied system reason, `right: Ok({"request_id":"request-1","status":"pending"})`.

Old:

```text
    let segment = resource
        .strip_prefix("elastos://")?
        .split(['/', '?', '#'])
        .next()?;
```

New:

```text
    let segment = resource
        .strip_prefix("elastos://")?
        .split(['/', '?', '#'])
        .next()?
        .to_lowercase();
    let segment = segment.as_str();
```

### Docs

`standin-runtime/README.md:65` adds one paragraph immediately before `## Callers`: `post_capability_request` denies a system-backend resource and a generic wallet resource before `seed_request`; the compare is case-sensitive on the text before the first `/`, `?` or `#`; the Ok body is `denied` and the handler's reason with no `request_id`, token or error; `elastos://wallet/meta/status` with `read` and `elastos://content/...` still store; a stopped instance still answers `instance is not live`; a PASS gives the Runtime no A6 credit for this denial. The RA-1 section, the RI-1 to RI-4 section and the settlement paragraph keep their bytes, and so do the ended-instance, cap, revoke and operation paragraphs.

`RUNBOOK.md:749` gains one paragraph after the last stand-in paragraph: `standin_system_and_wallet_requests_never_become_pending` is this stand-in, and a PASS there gives the Runtime no A6 credit for this denial. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged; `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.19 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 263.67 seconds (4m23.67s), inside the 600-second bound. Targets in order: lib 69 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.19 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_system_and_wallet_requests_never_become_pending -- --exact` exit 0, 1 passed and 0 failed, real 0.13 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The check compares a resource scheme segment at `standin-runtime/mod.rs:1336-1348`; it names no code or content identity and adds no route. |
| 2. Capsule, Home or UI gains ungranted access? | No | A denied request stores nothing and mints no token at `:383-385`; Home and the UI hold nothing new. |
| 3. A second path or a second copy of one rule? | No | The one rule lives in `prestore_denial` at `:1332`; `post_capability_request` reaches it once at `:383`, `seed_request` stays the only writer at `:387`, and the reasons have one copy each. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | Both denials return `denied` with the handler's exact reason at `:1336-1348`, and a stopped instance still returns `instance is not live` at `:380-382`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The stand-in stores or denies one record; no capsule code, import, world or Bus call changes. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_system_and_wallet_requests_never_become_pending` at `:7679`; the twelve plants each fail it, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The denial matches no identity claim, the phase gate at `:380-382` stays a separate admission decision, and a denied request mints no allowance. |

A passing row gives the real Runtime no A6 credit for this denial.

## 075 — One hostcall records the capsule's request

075: `bridge_envelope` is the one hostcall. A `request_capability` line calls `post_capability_request` for the given capsule id. A `resource_invoke` line calls `authorise` for that capsule id. `principal` does not choose the caller. `standin_bridge_envelope_records_the_capsule_request` fails on each of the fourteen hand-run plants and passes when they are restored. A PASS gives the Runtime no A3 credit.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md:231-234`, "Request flow", steps 6 and 7:

```text
6. The Agent Host submits the proposed operation to Runtime as the active agent
   principal and session.
7. Runtime verifies the exact resource, action, operation, principal, session,
   capsule, grant, expiry, and revocation state.
```

This task is the hostcall the component runner already makes for those two steps. It is not a second runner. Home still only shows the pending request.

### Quotes from the call shape (read only, not imported)

`elastos/crates/elastos-compute/src/providers/mod.rs:10-11` names the hostcall. The arguments are the envelope line, the capsule id, and the principal. The `Ok` string is one response envelope:

```text
pub type BridgeHostcall =
    Arc<dyn Fn(&str, &str, Option<&str>) -> std::result::Result<String, String> + Send + Sync>;
```

`elastos/crates/elastos-compute/src/providers/component.rs:323-328`, `call_bridge`, builds one line and calls that hostcall:

```text
        let line = guest_bus::bridge_envelope_json(1, request)
            .map_err(|err| bus_error("internal", err.to_string()))?;
        let raw = hostcall(&line, &self.capsule_id, self.principal_id.as_deref())
            .map_err(|err| bus_error("internal", err))?;
        let envelope: ResponseEnvelope =
            serde_json::from_str(&raw).map_err(|err| bus_error("internal", err.to_string()))?;
```

`elastos/crates/elastos-guest/src/bus.rs:81-83`, `bridge_envelope_json`, is the one line builder. This lane does not call it.

### Quotes from the envelope (read only, not imported)

`elastos/crates/elastos-guest/src/runtime.rs:82-85`, `RequestEnvelope`, is `id` plus `request`. `RuntimeRequest` at `:19-36` carries `request_capability` with `resource`, `action` and `reason`, and `resource_invoke` with `uri`, `operation`, `body` and `token`:

```text
pub struct RequestEnvelope {
    pub id: RequestId,
    pub request: RuntimeRequest,
}
```

```text
    RequestCapability {
        resource: String,
        action: String,
        reason: String,
    },
    ResourceInvoke {
        uri: String,
        operation: String,
        body: serde_json::Value,
        token: String,
    },
```

A line is JSON `{"id": <number>, "request": {"type": ...}}`.

### Code

- `bridge_envelope` at `standin-runtime/mod.rs:403` is the only new public method. The doc comment starts `Lab test seam, not a route.` `let _ = principal` at `:409` keeps the name and does not choose the caller. A line `serde_json::from_str` rejects returns `Err` whose text starts `Invalid JSON`. `bridge_id` at `:1434` reads a numeric `id`, uses `0` when `id` is absent, and returns `Invalid JSON: id must be a number` for any other present value. `bridge_request` at `:1447` returns `Invalid JSON: request must be an object` when `request` is missing or not an object. Neither stores.
- `request_capability` builds `{"resource","action","reason"}` in `capability_fields` at `:1459` and calls `post_capability_request` at `:421` with `Caller::Client { session_id: capsule_id }`. A missing `resource` or `action` is omitted, so that method's body check stays the one validation. A present field is copied with its JSON type. A missing `reason` is `""`. The method does not call `seed_request` and does not push onto the request store.
- `resource_invoke` reads `token` in `invoke_token` at `:1479`. A missing `token` is `""`. A non-string `token` is `Err` `Invalid JSON: token must be a string` and does not call `authorise`. A string `token` calls `authorise` at `:431` with `Caller::Client { session_id: capsule_id }`. The arm does not read `uri`, `operation` or `body`.
- `Ok` from `post_capability_request` becomes `{"id","response":{"type":"ok","data":...}}` through `bridge_ok` at `:1487`. `Ok(())` from `authorise` uses that same shape with `data` null. `Err` from either call, and any other `type`, becomes `{"id","response":{"type":"error","code":"denied","message":...}}` through `bridge_error` at `:1494`. There is no `token` key. `post_capability_request` and `authorise` keep their bodies. `admit_resident`, `post_capsules`, `launch_two_running` and `seed_request` stay. No new request store, no wasmtime type, no `ComponentProvider` and no child process.

### Tests

`standin_bridge_envelope_records_the_capsule_request` at `standin-runtime/mod.rs:8200` in the module's `#[cfg(test)]`, passing with no operator and no probe build. It reuses `launch_two_running`, `request_entries`, `grant_record`, `pending_request` and `assert_live_request_ids_empty`. Assertion text says the stand-in did the work. Each `Ok` is parsed as one JSON object with no trailing text, and the whole envelope is compared, including the echoed `id`, `code` `denied`, present `data` (null on a successful invoke) and no `token` key.

- `launch_two_running` leaves `component-1` and `component-2` `running` with cause `""`. `seed_grant` stores `req-once` on `component-1`, resource `localhost://Public/resident-instances/shared.txt`, action `read`, duration `once`, `granted_at` 1, life `Live`, `session_ended` false.
- A missing `request`, a non-object `request`, and a JSON value that is not an object are each `Err` `Invalid JSON: request must be an object`. Both request lists stay empty and `next_request` stays 1. A present nonnumeric `id` (`"7"`, `true`, `7.5`, `null`, `-1`) is `Err` `Invalid JSON: id must be a number` and stores nothing.
- The capability line `{"id":7,"request":{"type":"request_capability","resource":"localhost://Public/resident-instances/shared.txt","action":"read","reason":"read shared"}}` for `component-1` and principal `Some("person-a")` is `Ok`. `id` is 7, `response.type` is `ok`, and `response.data` is `{"status":"pending","request_id":"request-1"}`. `component-1` has that one pending request. `component-2` is empty. The same line for `component-2` and principal `None` stores `request-2` there, and `component-1` still has only `request-1`.
- The `https://example` line is `Ok` with `response.message` `Unsupported resource scheme. Allowed: elastos://, localhost://` and stores no `request-3`. `not json` is `Err` and the text contains `Invalid JSON`, and that text is not the request-object or id refusal. `{"id":7,"request":{"type":"ping"}}`, a request with no `type`, and a non-string `type` are `unsupported bridge request` and store nothing further.
- An omitted `id` echoes `0` and stores `request-3`. An omitted `reason` stores `request-4` with reason `""`. A missing `resource`, a missing `action`, a numeric `resource`, a numeric `action`, a numeric `reason` and action `jump` are the existing `post_capability_request` reasons: `request body needs resource`, `request body needs action`, `request resource must be a string`, `request action must be a string`, `request reason must be a string`, and `Invalid action: jump. Expected: read, write, execute, delete, message, admin`. None of them stores `request-5`.
- A non-string `token` is `Err` `Invalid JSON: token must be a string`. An omitted `token` is `Ok` with message `unknown grant: ` and echoed id `9`. `grant_record` for `req-once` stays `(Life::Live, false)`.
- The invoke line `{"id":8,"request":{"type":"resource_invoke","uri":"localhost://Public/resident-instances/shared.txt","operation":"read","body":{},"token":"req-once"}}` for `component-2` and principal `Some("component-1")` is `wrong capsule: expected component-1, got component-2`, and the grant stays `(Life::Live, false)`. The same line for `component-1` and principal `Some("person-a")` is `ok` with `data` null, and the grant is `(Life::Exhausted, false)`. A second owner invoke is `grant is not live: Exhausted`. Both instances stay `running` with cause `""`. The shell live-grant `request_id` set is empty.

### Hand-run falsifiers

No `falsifiers.json` id and no new id. Each plant ran alone, the planted crate compiled, and it was restored before the next. The command was `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_bridge_envelope_records_the_capsule_request -- --exact`. Every planted run exited 101 with that test failed on its assertion. After the last restore, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows the candidate only, with no plant. `standin-runtime/mod.rs` SHA-256 is `ff371dbcd18bbfa549dbe1f480a66c6060717a6cc6a1cbaaa18f9de75bcae57e` before and after the plants. A planted panic line that moved is named with the restored line.

F-standin-bridge-stub: the start of `bridge_envelope` returns the canned `Ok` before the line is parsed. Planted run failed at `mod.rs:8248:13` (`:8244` restored): `the stand-in did the work: a request that is not an object is refused: {"id":7} Ok("{\"id\":7,\"response\":{\"type\":\"ok\",\"data\":{\"status\":\"pending\",\"request_id\":\"request-1\"}}}")`.

Old:

```text
    ) -> Result<String, String> {
        let _ = principal;
```

New:

```text
    ) -> Result<String, String> {
        return Ok(
            r#"{"id":7,"response":{"type":"ok","data":{"status":"pending","request_id":"request-1"}}}"#
                .to_owned(),
        );
        let _ = principal;
```

F-standin-bridge-fixed-session: the `request_capability` arm calls `post_capability_request` with `component-1` for every capsule id. Planted run failed at `mod.rs:8304:9`: `the stand-in did the work: component-2 has that one pending request`, `left: []`, `right` the `request-2` entry for `component-2`.

Old:

```text
                let capability_caller = Caller::Client {
                    session_id: capsule_id,
                };
```

New:

```text
                let capability_caller = Caller::Client {
                    session_id: "component-1",
                };
```

F-standin-bridge-principal-caller: the `resource_invoke` arm uses `principal.unwrap_or(capsule_id)` as the `Caller` session. Planted run failed at `mod.rs:8160:9` (`:8159` restored): `the stand-in did the work: a grant for the other capsule is refused`, `left` `ok` with `data` null, `right` the `wrong capsule` error envelope.

Old:

```text
            "resource_invoke" => {
                let token = invoke_token(request)?;
                let invoke_caller = Caller::Client {
                    session_id: capsule_id,
                };
```

New:

```text
            "resource_invoke" => {
                let token = invoke_token(request)?;
                let invoke_session = principal.unwrap_or(capsule_id);
                let invoke_caller = Caller::Client {
                    session_id: invoke_session,
                };
```

F-standin-bridge-request-object: a missing or non-object `request` skips the object check. Planted run failed at `mod.rs:8244:13`: `a request that is not an object is refused: {"id":7}`, `Ok` of the `unsupported bridge request` envelope.

Old:

```text
fn bridge_request(envelope: &Value) -> Result<&Value, String> {
    match envelope.get("request") {
        Some(request) if request.is_object() => Ok(request),
        _ => Err("Invalid JSON: request must be an object".to_owned()),
    }
}
```

New:

```text
fn bridge_request(envelope: &Value) -> Result<&Value, String> {
    match envelope.get("request") {
        Some(request) => Ok(request),
        _ => Ok(envelope),
    }
}
```

F-standin-bridge-default-id: an omitted `id` becomes `7`. Planted run failed at `mod.rs:8137:9`: `an omitted id is 0 and stores request-3`, `left` id `7`, `right` id `0`.

Old:

```text
        None => Ok(0),
```

New:

```text
        None => Ok(7),
```

F-standin-bridge-default-reason: an omitted `reason` is stored as `read shared`. Planted run failed at `mod.rs:8415:9`: `an omitted reason is stored as an empty string`, `request-4` `reason` `read shared` against `""`.

Old:

```text
        None => Value::String(String::new()),
```

New:

```text
        None => Value::String("read shared".to_owned()),
```

F-standin-bridge-default-token: an omitted `token` is `req-once`. Planted run failed at `mod.rs:8159:9`: `an omitted token is an unknown grant`, `left` `ok` with `data` null, `right` message `unknown grant: `.

Old:

```text
        None => Ok(""),
```

New:

```text
        None => Ok("req-once"),
```

F-standin-bridge-fixed-id: every response echoes id `7`. Planted run failed at `mod.rs:8159:9`: `any other request type is unsupported`, `left` id `7`, `right` id `6`.

Old:

```text
        serde_json::to_string(&json!({
            "id": id,
            "response": response,
        }))
```

New:

```text
        serde_json::to_string(&json!({
            "id": 7,
            "response": response,
        }))
```

F-standin-bridge-error-code: the error envelope uses `code` `error`. Planted run failed at `mod.rs:8159:9`: `an unsupported scheme is refused`, `left` `code` `error`, `right` `code` `denied`.

Old:

```text
fn bridge_error(message: &str) -> Value {
    json!({
        "type": "error",
        "code": "denied",
        "message": message,
    })
}
```

New:

```text
fn bridge_error(message: &str) -> Value {
    json!({
        "type": "error",
        "code": "error",
        "message": message,
    })
}
```

F-standin-bridge-omit-null: a null `data` is omitted. Planted run failed at `mod.rs:8141:9` (`:8137` restored): `the owner invoke authorises component-1`, `left` a response with no `data`, `right` `data` null.

Old:

```text
fn bridge_ok(data: Value) -> Value {
    json!({
        "type": "ok",
        "data": data,
    })
}
```

New:

```text
fn bridge_ok(data: Value) -> Value {
    if data.is_null() {
        json!({ "type": "ok" })
    } else {
        json!({
            "type": "ok",
            "data": data,
        })
    }
}
```

F-standin-bridge-token-field: the envelope gains `token`. Planted run failed at `mod.rs:8138:9` (`:8137` restored): `component-1's capability line stores request-1`, `left` has `token` `req-once`, `right` has no `token`.

Old:

```text
        serde_json::to_string(&json!({
            "id": id,
            "response": response,
        }))
```

New:

```text
        serde_json::to_string(&json!({
            "id": id,
            "response": response,
            "token": "req-once",
        }))
```

F-standin-bridge-id-coerce: a nonnumeric `id` becomes `0`. Planted run failed at `mod.rs:8262:13` (`:8264` restored): `a nonnumeric id is refused: "7"`, `Ok` of id `0` and `request-1`.

Old:

```text
        Some(id) => id
            .as_u64()
            .ok_or_else(|| "Invalid JSON: id must be a number".to_owned()),
```

New:

```text
        Some(id) => Ok(id.as_u64().unwrap_or(0)),
```

F-standin-bridge-token-coerce: a non-string `token` becomes `""`. Planted run failed at `mod.rs:8498:13`: `a non-string token is refused: 1`, `Ok` of the `unknown grant: ` envelope.

Old:

```text
        Some(_) => Err("Invalid JSON: token must be a string".to_owned()),
```

New:

```text
        Some(_) => Ok(""),
```

F-standin-bridge-field-coerce: missing and non-string capability fields are forced to strings before `post_capability_request`. Planted run failed at `mod.rs:8166:9` (`:8159` restored): `a missing resource reaches post_capability_request`, `left` `Unsupported resource scheme. Allowed: elastos://, localhost://`, `right` `request body needs resource`.

Old:

```text
fn capability_fields(request: &Value) -> Value {
    let mut body = Map::new();
    if let Some(resource) = request.get("resource") {
        body.insert("resource".to_owned(), resource.clone());
    }
    if let Some(action) = request.get("action") {
        body.insert("action".to_owned(), action.clone());
    }
    let reason = match request.get("reason") {
        None => Value::String(String::new()),
        Some(reason) => reason.clone(),
    };
    body.insert("reason".to_owned(), reason);
    Value::Object(body)
}
```

New:

```text
fn capability_fields(request: &Value) -> Value {
    let mut body = Map::new();
    let resource = request
        .get("resource")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let action = request
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let reason = request
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    body.insert("resource".to_owned(), Value::String(resource));
    body.insert("action".to_owned(), Value::String(action));
    body.insert("reason".to_owned(), Value::String(reason));
    Value::Object(body)
}
```

### Docs

`standin-runtime/README.md` adds one paragraph immediately before `## Callers`: `bridge_envelope` is the one hostcall; two-capsule-run passes the envelope line, the capsule id and the principal and does not copy this module; this lane does not run the component bytes; a capability line calls `post_capability_request` for that capsule id; an invoke line calls `authorise` for that capsule id, and the principal argument does not choose the caller; a PASS gives the Runtime no A3 credit; `session_id` still equals the instance id. The RA-1 section, the RI-1 to RI-4 section, the settlement paragraph, and the request, grant, cap and revoke paragraphs keep their bytes.

`RUNBOOK.md` gains one paragraph after the last stand-in paragraph: `standin_bridge_envelope_records_the_capsule_request` is this stand-in, two-capsule-run owns the real-bytes run, and a PASS here gives the Runtime no A3 credit. Every other RUNBOOK paragraph keeps its bytes.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. `git diff` for `src/harness.rs`, `src/census.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.14 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 262.65 seconds, inside the 600-second bound. Targets in order: lib 70 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.15 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_bridge_envelope_records_the_capsule_request -- --exact` exit 0, 1 passed and 0 failed, real 0.12 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | `capability_fields` at `standin-runtime/mod.rs:1459` copies the request fields into the existing body and names no bundle or content hash. |
| 2. Capsule, Home or UI gains ungranted access? | No | `let _ = principal` at `:409` discards the principal, and both arms pass `capsule_id` at `:418-420` and `:428-430`. |
| 3. A second path or a second copy of one rule? | No | The capability arm calls `post_capability_request` once at `:421`, the invoke arm calls `authorise` once at `:431`, and this method does not call `seed_request`. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`; `elastos/` is untouched and quoted only. |
| 5. Refusals deny by default with a clear reason? | Yes | `bridge_request` at `:1447`, `bridge_id` at `:1434` and `invoke_token` at `:1479` return `Invalid JSON` reasons, and `bridge_error` at `:1494` uses `code` `denied` plus the existing reason text. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | `bridge_envelope` at `:403` is the one hostcall and starts no component bytes, process or wasmtime store. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_bridge_envelope_records_the_capsule_request` at `:8200`; the fourteen plants each fail it, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | The capsule id is only the caller session at `:418` and `:428`; `post_capability_request` still admits the instance, and `authorise` still decides the grant. |

A passing row gives the real Runtime no A3 credit. two-capsule-run owns the real-bytes run.

## 076 — Launch principal protects the stored write

076: `bind_verified_principal` stores the principal the launch verified. `post_capsules` copies it onto the new instance. `protected_write` and `protected_read` resolve `Users/self` and `UsersAI/self` from that principal, then `authorise`, and one map stores the bytes. `standin_protected_storage_uses_the_launch_principal` fails on each of the sixteen hand-run plants and passes when they are restored. A PASS gives the Runtime no A15 credit. The UsersAI binding rows stay blocked.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, "State ownership":

```text
- Agent state is rooted under the agent principal's `UsersAI/...` space.
```

```text
This document does not freeze the exact path layout below `Users/...` or
`UsersAI/...`.
```

`docs/AGENT_ARCHITECTURE.md`, "Request flow", step 2:

```text
2. Runtime resolves and binds the human principal, agent principal, proof,
   Agent Host capsule identity, session, and launch authority.
```

`git show 513988ebd:lab/runtime-asks/04-protected-storage-bridge-entry.md`, "The ask":

```text
The A15 host can send an approved journal write through the Runtime's own
protected storage path, so the write is stored under the person's protected
root.
```

`git show 513988ebd:lab/runtime-asks/05-usersai-principal-root-alias.md`, "The ask":

```text
A guest that names `UsersAI/self` reaches the root of the agent principal that
the Runtime verified for the launch.
```

`examples/agent-host/handoff/USERSAI-JOURNAL.md`:

```text
The guest only ever names `UsersAI/self`. The Runtime rewrites `self` to the active agent principal's root, the same way it rewrites `Users/self` today (`resource_bridge.rs` `scope_current_user_alias`). Any other `UsersAI/<root>` from the guest is refused.
```

Form A and Form B stay in that ask. This lane does not edit `elastos/`.

### Plants

Each plant was applied alone, the crate compiled, and `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_protected_storage_uses_the_launch_principal -- --exact` failed on an assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id.

F-standin-principal-constant: the `UsersAI/self` arm returns `localhost://UsersAI/ada` plus the suffix. Failed at `standin-runtime/mod.rs:8930:9`: `a Starting instance stores the approved write`, left `Ok("localhost://UsersAI/ada/journal")`, right `Ok("localhost://UsersAI/763281cf1e57227a6b99d89d/journal")`.

Old:

```text
                return Ok(format!("localhost://UsersAI/{digest}{suffix}"));
```

New:

```text
                return Ok(format!("localhost://UsersAI/ada{suffix}"));
```

F-standin-principal-copy: `post_capsules` stores `ada` in place of the bound principal. Failed at `standin-runtime/mod.rs:8930:9`: `a Starting instance stores the approved write`, left `Ok("localhost://UsersAI/fdee430d40bd57deeac186cd/journal")`, right `Ok("localhost://UsersAI/763281cf1e57227a6b99d89d/journal")`.

Old:

```text
            principal,
```

New:

```text
            principal: principal.map(|_| "ada".to_owned()),
```

F-standin-protected-stub: the start of `protected_write` returns `Ok` of the guest uri. Failed at planted `standin-runtime/mod.rs:8832:9` (restored `:8831`): `an unbound launch requires the verified principal`, left `Ok("localhost://UsersAI/self/journal")`, right `Err((400, "requires the principal from the verified launch"))`.

Old:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

New:

```text
        return Ok(uri.to_owned());
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

F-standin-protected-guest-key: the write stores under the guest uri. The read still looks up the resolved uri. Failed at `standin-runtime/mod.rs:8940:9`: `a Starting instance reads the approved write`, left `Err((404, "protected object is absent"))`, right `Ok` of `start-v1`.

Old:

```text
            .insert(resolved.clone(), bytes.to_vec());
```

New:

```text
            .insert(uri.to_owned(), bytes.to_vec());
```

F-standin-read-skip-auth: `protected_read` skips `authorise`. Failed at planted `standin-runtime/mod.rs:9084:9` (restored `:9089`): `an unknown grant cannot read`, left `Ok` of `journal-v1`, right `Err((400, "unknown grant: req-missing"))`.

Old:

```text
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
        self.protected_objects
            .get(&resolved)
```

New:

```text
        let _ = request_id;
        self.protected_objects
            .get(&resolved)
```

F-standin-auth-before-resolve: `protected_write` calls `authorise` before `resolve_protected_uri`. Failed at `standin-runtime/mod.rs:8831:9`: `an unbound launch requires the verified principal`, left `Err((400, "unknown grant: req-none"))`, right `Err((400, "requires the principal from the verified launch"))`.

Old:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
```

New:

```text
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

F-standin-auth-before-uri: a resolver error other than the instance, `..`, or missing-principal refusal still calls `authorise` before the error returns. Failed at planted `standin-runtime/mod.rs:8785:9` (restored `:8774`): `a once grant does not pass another UsersAI root spends nothing`, left `(Exhausted, false)`, right `(Live, false)`.

Old:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
        Ok(resolved)
```

New:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri);
        let early = matches!(
            &resolved,
            Err((400, reason))
                if reason == "requires the principal from the verified launch"
                    || reason == "protected path rejects .."
                    || reason.starts_with("unknown instance")
                    || reason.starts_with("instance is not live")
        );
        if !early {
            self.authorise(
                Caller::Client {
                    session_id: instance_id,
                },
                request_id,
            )?;
        }
        let resolved = resolved?;
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
        Ok(resolved)
```

F-standin-bind-skip-validation: `bind_verified_principal` stores any principal on a known path and returns `Ok` otherwise. Failed at planted `standin-runtime/mod.rs:8851:9` (restored `:8858`): `an empty principal is refused`, left `Ok(())`, right `Err((400, "verified launch needs a principal"))`.

Old:

```text
        if principal.is_empty() {
            return Err((400, "verified launch needs a principal".to_owned()));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        if row.principal.is_some() {
            return Err((400, "verified principal already bound".to_owned()));
        }
        row.principal = Some(principal.to_owned());
        Ok(())
```

New:

```text
        if let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) {
            row.principal = Some(principal.to_owned());
        }
        Ok(())
```

F-standin-bind-retroactive: a later bind copies the principal onto an instance that already exists. Failed at planted `standin-runtime/mod.rs:8892:9` (restored `:8885`): `a later bind leaves the instance already created`, left `Ok("localhost://UsersAI/763281cf1e57227a6b99d89d/journal")`, right `Err((400, "requires the principal from the verified launch"))`.

Old:

```text
        row.principal = Some(principal.to_owned());
        Ok(())
```

New:

```text
        let name = row.name.clone();
        let bound = principal.to_owned();
        row.principal = Some(bound.clone());
        for instance in &mut self.instances {
            if instance.name == name && instance.principal.is_none() {
                instance.principal = Some(bound.clone());
            }
        }
        Ok(())
```

F-standin-skip-instance-checks: a missing instance continues into the resolver. Failed at planted `standin-runtime/mod.rs:9424:9` (restored `:9433`): `an unknown instance cannot write`, left `Err((400, "requires the principal from the verified launch"))`, right `Err((400, "unknown instance: component-missing"))`.

Old:

```text
        let Some(instance) = self
            .instances
            .iter()
            .find(|instance| instance.id == instance_id)
        else {
            return Err(unknown_instance(instance_id));
        };
        if !matches!(
            instance.phase,
            ResidentStatus::Starting | ResidentStatus::Running
        ) {
            return Err(not_live(instance.phase));
        }
```

New:

```text
        let principal_owned = self
            .instances
            .iter()
            .find(|instance| instance.id == instance_id)
            .and_then(|instance| instance.principal.clone());
```

The `..` check and the principal read stay, and the principal read uses `principal_owned`.

F-standin-running-only: only `Running` is admitted. Failed at planted `standin-runtime/mod.rs:8927:9` (restored `:8930`): `a Starting instance stores the approved write`, left `Err((400, "instance is not live: starting"))`, right `Ok("localhost://UsersAI/763281cf1e57227a6b99d89d/journal")`.

Old:

```text
        if !matches!(
            instance.phase,
            ResidentStatus::Starting | ResidentStatus::Running
        ) {
            return Err(not_live(instance.phase));
        }
```

New:

```text
        if instance.phase != ResidentStatus::Running {
            return Err(not_live(instance.phase));
        }
```

F-standin-resolver-lookalike: `Users/self` accepts any suffix. Failed at planted `standin-runtime/mod.rs:8767:9` (restored `:8769`): `a Users/self prefix lookalike is refused`, left `Ok("localhost://Users/763281cf1e57227a6b99d89dish/journal")`, right the Users-root refusal.

Old:

```text
        if let Some(suffix) = uri.strip_prefix("localhost://Users/self") {
            if suffix.is_empty() || suffix.starts_with('/') {
                return Ok(format!("localhost://Users/{digest}{suffix}"));
            }
        }
```

New:

```text
        if let Some(suffix) = uri.strip_prefix("localhost://Users/self") {
            return Ok(format!("localhost://Users/{digest}{suffix}"));
        }
```

F-standin-resolver-users-root: the active `Users` root is refused. Failed at planted `standin-runtime/mod.rs:9332:9` (restored `:9337`): `the active Users root replaces the stored bytes`, left the Users-root refusal, right `Ok("localhost://Users/763281cf1e57227a6b99d89d")`.

Old:

```text
        let users_root = format!("localhost://Users/{digest}");
        let users_child = format!("{users_root}/");
        if uri == users_root || uri.starts_with(&users_child) {
            return Ok(uri.to_owned());
        }
```

New: that block is removed.

F-standin-resolver-unsupported: any other uri is stored as itself. Failed at planted `standin-runtime/mod.rs:8766:9` (restored `:8769`): `an elastos uri is refused`, left `Ok("elastos://content/journal")`, right `Err((400, "protected storage needs a Users/self or UsersAI/self resource"))`.

Old:

```text
        Err((
            400,
            "protected storage needs a Users/self or UsersAI/self resource".to_owned(),
        ))
```

New:

```text
        Ok(uri.to_owned())
```

F-standin-ignore-replacement: a second write leaves the first bytes. Failed at planted `standin-runtime/mod.rs:9344:9` (restored `:9342`): `the bare Users read sees the replacement`, left `Ok` of `bare-users`, right `Ok` of `root-v2`.

Old:

```text
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
        Ok(resolved)
```

New:

```text
        if !self.protected_objects.contains_key(&resolved) {
            self.protected_objects
                .insert(resolved.clone(), bytes.to_vec());
        }
        Ok(resolved)
```

F-standin-store-before-auth: `protected_write` stores before `authorise`. Failed at `standin-runtime/mod.rs:9208:9`: `a missing grant stores nothing`, left `Ok` of `missing-v1`, right `Ok` of `journal-v1`.

Old:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
```

New:

```text
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
        self.protected_objects
            .insert(resolved.clone(), bytes.to_vec());
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
```

### Docs

`standin-runtime/README.md` adds one paragraph immediately before `## Callers`. `bind_verified_principal` stores the principal the launch verified. The launch body still rejects `principal_id`. `protected_write` stores under `Users/self` or `UsersAI/self` resolved from that principal. The digest is `identity::sha256`. A constant principal is not the root. Another `UsersAI` root is refused. A PASS gives the Runtime no A15 credit, and the UsersAI binding rows stay blocked. `session_id` still equals the instance id. The hostcall paragraph stays. The launch, list, and settlement paragraphs stay. There is no heading named RI-1 to RI-4.

`RUNBOOK.md` gains one paragraph after the last stand-in paragraph: `standin_protected_storage_uses_the_launch_principal` is this stand-in, and a PASS there gives the Runtime no A15 credit. Every other RUNBOOK paragraph stays.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. `git diff` for `src/harness.rs`, `src/census.rs`, `src/identity.rs`, `tests/effects.rs`, `tests/common/grants.rs`, `GAPS.md`, `falsifiers.json`, `Cargo.toml` and `Cargo.lock` printed nothing. The changed files are `standin-runtime/mod.rs`, `standin-runtime/README.md`, `RUNBOOK.md` and this `LOG.md`. After the plants were restored, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` has no plant.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.20 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 271.93 seconds, inside the 600-second bound. Targets in order: lib 71 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.20 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_protected_storage_uses_the_launch_principal -- --exact` exit 0, 1 passed and 0 failed, real 0.13 seconds.

### Principles check

| Question | Yes/No | Evidence |
| --- | --- | --- |
| 1. New name or URL where a hash belongs? | No | The root is the first 24 characters of `identity::sha256` at `standin-runtime/mod.rs:839`. The principal text is not copied into the root. |
| 2. Capsule, Home or UI gains ungranted access? | No | `protected_write` calls `authorise` at `:774` before the map insert at `:780`. A refusal stores nothing. |
| 3. A second path or a second copy of one rule? | No | `resolve_protected_uri` at `:812` is the one resolver. `post_capsules` copies the principal at `:978`. `bind_verified_principal` is the one store at `:915`. |
| 4. Runtime core grows? | No | Every edit is under `lab/agent-conformance/`. `elastos/` is untouched. |
| 5. Refusals deny by default with a clear reason? | Yes | `resolve_protected_uri` at `:816-858` returns the instance, `..`, principal, `UsersAI`, `Users`, and other-uri reasons before `authorise`. |
| 6. Capsule logic stays inside and uses granted Bus calls? | Yes | The stand-in keeps one in-memory map. It opens no file and adds no `wasi` import. |
| 7. Named tests and caught falsifiers prove the rule? | Yes | `standin_protected_storage_uses_the_launch_principal` at `:8787`. The sixteen plants each fail it, and the restored test passes. |
| 8. Identity, admission and allowance stay separate? | Yes | `bind_verified_principal` at `:901` stores the verified principal. `admit_resident` at `:864` still only admits the path. `authorise` at `:741` still spends the grant. |

A passing row gives the real Runtime no A15 credit. The UsersAI binding rows stay blocked.

### Round 2 — grant resource and action

`protected_write` and `protected_read` present the guest uri and `write` or `read` to `authorise_presented`, the one check `authorise` calls. After the unknown, not-live and wrong-caller refusals, a different action is `wrong action` and a different resolved object is `wrong resource`. Either refusal stores nothing and spends nothing. `authorise` stays `(&mut self, caller, request_id)`. No `falsifiers.json` id.

Each plant was applied alone, the crate compiled, and `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_protected_storage_uses_the_launch_principal -- --exact` failed on an assertion. The file was restored before the next plant. Restored, that test passes.

F-standin-grant-ignores-presented: the presented match is dropped. Failed at planted `standin-runtime/mod.rs:8984:9` (restored `:8999`): `a Starting write grant cannot read`, left `Ok` of `start-v1`, right `Err((403, "wrong action: expected write, got read"))`.

Old:

```text
        if let Some((requested, action)) = presented {
            let grant_action = self.grants[index].action.clone();
            let grant_resource = self.grants[index].resource.clone();
            if grant_action != action {
                return Err(wrong_action(&grant_action, action));
            }
            let session_id = self.grants[index].session_id.clone();
            let wanted = self.resolve_protected_uri(&session_id, requested)?;
            let granted = match self.resolve_protected_uri(&session_id, &grant_resource) {
                Ok(uri) => uri,
                Err(_) => return Err(wrong_resource(&grant_resource, requested)),
            };
            if wanted != granted {
                return Err(wrong_resource(&grant_resource, requested));
            }
        }
```

New:

```text
        let _ = presented;
```

F-standin-read-ignores-grant: `protected_read` calls `authorise` with no presented uri or action. Failed at planted `standin-runtime/mod.rs:8998:9` (restored `:8999`): `a Starting write grant cannot read`, left `Ok` of `start-v1`, right `Err((403, "wrong action: expected write, got read"))`.

Old:

```text
        self.authorise_presented(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
            Some((uri, "read")),
        )?;
```

New:

```text
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
```

F-standin-write-ignores-grant: `protected_write` calls `authorise` with no presented uri or action. Failed at planted `standin-runtime/mod.rs:9186:9` (restored `:9187`): `a read-only journal grant cannot write another path`, left `Ok("localhost://UsersAI/763281cf1e57227a6b99d89d/other")`, right `Err((403, "wrong action: expected read, got write"))`.

Old:

```text
        self.authorise_presented(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
            Some((uri, "write")),
        )?;
```

New:

```text
        self.authorise(
            Caller::Client {
                session_id: instance_id,
            },
            request_id,
        )?;
```

F-standin-spend-before-match: a `once` grant is stored `Exhausted` before the presented match. Failed at `standin-runtime/mod.rs:9464:9`: `a once journal grant cannot write another path`, left `Err((400, "grant is not live: Exhausted"))`, right `Err((403, "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other"))`.

Old: the `duration == "once"` assignment stays after the presented match.

New: that assignment is moved to just before `if let Some((requested, action)) = presented`.

F-standin-resource-before-action: the resolved-object compare runs before the action compare. Failed at `standin-runtime/mod.rs:9187:9`: `a read-only journal grant cannot write another path`, left `Err((403, "wrong resource: expected localhost://UsersAI/self/journal, got localhost://UsersAI/self/other"))`, right `Err((403, "wrong action: expected read, got write"))`.

Old: `wrong_action` returns before `resolve_protected_uri` compares the objects.

New: the object compare returns `wrong_resource` before `wrong_action`.

### Round 2 gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. The forbidden `git diff` is empty. After the plants were restored, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` has no plant.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.17 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 282.72 seconds, inside the 600-second bound. Targets in order: lib 71 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.16 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_protected_storage_uses_the_launch_principal -- --exact` exit 0, 1 passed and 0 failed, real 0.17 seconds.

Round 2 principles: the allowance compare is `authorise_presented` at `standin-runtime/mod.rs:771`. `protected_write` calls it at `:806` and `protected_read` at `:829`, before any store. A mismatch returns `wrong action` or `wrong resource` and spends nothing. The root is still `identity::sha256` at `:873`. `bind_verified_principal` at `:935` and `admit_resident` at `:908` stay separate. `post_capsules` copies the principal at `:1012`. A PASS gives the Runtime no A15 credit. The UsersAI binding rows stay blocked.

## 077 — Bind the instance to its component hash

077: `bind_verified_component` stores the component hash the verified launch supplied. `post_capsules` copies that hash onto the new instance and is the only assignment of an instance hash. `component_hash` reads it. The launch body still rejects `component_hash`, and the list JSON does not carry it. `standin_instance_stores_the_verified_component_hash` fails on each hand-run plant and passes when they are restored. A PASS gives the Runtime no A3 credit. two-capsule-run owns the bytes.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Decision summary:

```text
- A capsule instance acts only in the context of its capsule identity,
  principal, session, granted capabilities, resources, and lifecycle.
```

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 2:

```text
2. Runtime resolves and binds the human principal, agent principal, proof,
   Agent Host capsule identity, session, and launch authority.
```

BACKLOG item 22:

```text
two-capsule-run owns the real-bytes run, and this lane binds the instance to the component hash before any A3 bytes credit.
```

```text
Bind a stand-in instance to the component hash it was launched from, before any A3 bytes credit. two-capsule-run owns the real-bytes run. This lane does not build a second runner.
```

Capsule identity here is the component hash. This task is that binding. It is not a second runner and it does not load bytes.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_instance_stores_the_verified_component_hash -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-hash-constant: `post_capsules` stores 64 `a` characters on every new instance. Failed at `src/../standin-runtime/mod.rs:10224:9`: `component-2 stores hash_b`, left `Ok` of 64 `a` characters, right `Ok` of 64 `b` characters.

Old:

```text
            principal,
            component_hash,
```

New:

```text
            principal,
            component_hash: Some("a".repeat(64)),
```

F-standin-hash-name: `post_capsules` stores the admit name as the instance hash. Failed at `src/../standin-runtime/mod.rs:10219:9`: `component-1 stores hash_a`, left `Ok("agent-a")`, right `Ok` of 64 `a` characters.

Old:

```text
            component_hash,
```

New:

```text
            component_hash: Some(name.clone()),
```

F-standin-hash-stub: the start of `component_hash` returns `Ok` of 64 `a` characters before it reads the instance. Failed at planted `src/../standin-runtime/mod.rs:10225:9` (restored `:10224`): `component-2 stores hash_b`, left `Ok` of 64 `a` characters, right `Ok` of 64 `b` characters.

Old:

```text
    pub fn component_hash(&self, instance_id: &str) -> Result<String, (u16, String)> {
        let Some(instance) = self
```

New:

```text
    pub fn component_hash(&self, instance_id: &str) -> Result<String, (u16, String)> {
        return Ok("a".repeat(64));
        let Some(instance) = self
```

F-standin-hash-retro: `bind_verified_component` writes the new hash onto instances already created for that path, matched by the admit name. Failed at planted `src/../standin-runtime/mod.rs:10292:9` (restored `:10285`): `a later bind leaves the instance already created`, left `Ok` of 64 `b` characters, right `Err((400, "instance has no verified component hash"))`.

Old:

```text
        row.component_hash = Some(hash.to_owned());
        Ok(())
```

New:

```text
        let name = row.name.clone();
        let bound = hash.to_owned();
        row.component_hash = Some(bound.clone());
        for instance in &mut self.instances {
            if instance.name == name {
                instance.component_hash = Some(bound.clone());
            }
        }
        Ok(())
```

F-standin-hash-length: `crate::report::hex` is called with the input length in place of 64. Failed at `src/../standin-runtime/mod.rs:10127:9`: `a 63-character hash is refused`, left `Ok(())`, right `Err((400, "component hash must be 64 lowercase hex characters"))`.

Old:

```text
        if !crate::report::hex(hash, 64) {
```

New:

```text
        if !crate::report::hex(hash, hash.len()) {
```

F-standin-hash-order-path: the path check runs before the empty-hash and hex checks. Failed at `src/../standin-runtime/mod.rs:10112:9`: `an empty hash is refused before the path`, left `Err((400, "unknown resident path: /capsules/missing"))`, right `Err((400, "verified launch needs a component hash"))`.

Old:

```text
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
```

New:

```text
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
```

F-standin-hash-order-rebind: an already-bound path is refused before the empty-hash and hex checks. Failed at planted `src/../standin-runtime/mod.rs:10157:9` (restored `:10155`): `an empty hash is refused before a rebind`, left `Err((400, "verified component hash already bound"))`, right `Err((400, "verified launch needs a component hash"))`.

Old:

```text
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        if row.component_hash.is_some() {
            return Err((400, "verified component hash already bound".to_owned()));
        }
        row.component_hash = Some(hash.to_owned());
        Ok(())
```

New:

```text
        if let Some(row) = self.admitted.iter().find(|row| row.path == path) {
            if row.component_hash.is_some() {
                return Err((400, "verified component hash already bound".to_owned()));
            }
        }
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
        row.component_hash = Some(hash.to_owned());
        Ok(())
```

F-standin-hash-empty-bypass: an empty hash returns `Ok` and stores nothing. Failed at `src/../standin-runtime/mod.rs:10107:9`: `an empty hash is refused`, left `Ok(())`, right `Err((400, "verified launch needs a component hash"))`.

Old:

```text
        if hash.is_empty() {
            return Err((400, "verified launch needs a component hash".to_owned()));
        }
```

New:

```text
        if hash.is_empty() {
            return Ok(());
        }
```

F-standin-hash-malformed-bypass: a hash `crate::report::hex` rejects returns `Ok`. Failed at planted `src/../standin-runtime/mod.rs:10114:9` (restored `:10117`): `a name is not a component hash`, left `Ok(())`, right `Err((400, "component hash must be 64 lowercase hex characters"))`.

Old:

```text
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
```

New:

```text
        if !crate::report::hex(hash, 64) {
            return Ok(());
        }
```

F-standin-hash-unknown-bypass: an unknown path returns `Ok`. Failed at `src/../standin-runtime/mod.rs:10147:9`: `an unknown path is refused`, left `Ok(())`, right `Err((400, "unknown resident path: /capsules/missing"))`.

Old:

```text
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Err((400, format!("unknown resident path: {path}")));
        };
```

New:

```text
        if !crate::report::hex(hash, 64) {
            return Err((
                400,
                "component hash must be 64 lowercase hex characters".to_owned(),
            ));
        }
        let Some(row) = self.admitted.iter_mut().find(|row| row.path == path) else {
            return Ok(());
        };
```

F-standin-hash-bound-bypass: a path that already has a hash returns `Ok` and keeps the stored hash. Failed at `src/../standin-runtime/mod.rs:10170:9`: `a second hash is refused`, left `Ok(())`, right `Err((400, "verified component hash already bound"))`.

Old:

```text
        if row.component_hash.is_some() {
            return Err((400, "verified component hash already bound".to_owned()));
        }
```

New:

```text
        if row.component_hash.is_some() {
            return Ok(());
        }
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. The forbidden `git diff` is empty. `git diff -- lab/agent-conformance/src/report.rs` is only `fn hex` to `pub(crate) fn hex`, with the same body. After the plants were restored, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` has no plant.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.15 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 267.46 seconds, inside the 600-second bound. Targets in order: lib 72 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.30 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_instance_stores_the_verified_component_hash -- --exact` exit 0, 1 passed and 0 failed, real 0.17 seconds.

Principles: the instance hash is the value `post_capsules` copies at `standin-runtime/mod.rs:1064`, checked by `crate::report::hex` at `:970` against `src/report.rs:350`. `bind_verified_component` at `:966` stores that hash on the admitted path at `:982` and does not mint an id. `component_hash` at `:990` reads the instance field. Empty, malformed, unknown-path and already-bound refusals are `:968`, `:971`, `:977` and `:980`. An unknown instance is `:996`. A missing hash is `:1001`. `admit_resident` at `:915` stays the admit. A PASS gives the Runtime no A3 credit. two-capsule-run owns the bytes.

## 078 — Shell lists every pending request

078: `get_capability_pending` answers `GET /api/capability/pending` from the one request store. A client is refused before that store is read. The list is every session's pending records, sorted by `session_id` then `request_id`. `expires_at` comes from `request_expires_at`, which is `requested_at` plus `REQUEST_TIMEOUT_SECS`. The list does not grant and does not settle. `standin_shell_lists_every_pending_request` fails on each hand-run plant and passes when they are restored. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.

The spec check seeds same-session ids in reverse order (`req-c` before `req-a`), denies `req-d` and asserts its omission, gives each request its own resource, action and reason, and seeds `req-sat` at `u64::MAX - 10` so expiry must saturate. The sorted shell order of the first three is still `req-a`, `req-c`, `req-b`.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 8:

```text
8. If additional consent is required, Runtime records a pending request and
   Home or Inbox presents it. The UI does not mint the grant itself.
```

This task is that list. It is not the grant and it does not store a decision.

`elastos/crates/elastos-server/src/api/handlers/capability.rs`, `ListPendingOutput` and `PendingRequestOutput`. The body's only key is `requests`. Each entry's keys are `request_id`, `session_id`, `resource`, `action`, `reason`, `requested_at` and `expires_at`. The route is `GET /api/capability/pending` in `elastos/crates/elastos-server/src/api/server.rs`. The shell check is the middleware, and the reason is `This endpoint requires shell privileges`.

The one timeout is `REQUEST_TIMEOUT_SECS` on this stand-in, value 300. `elastos/crates/elastos-runtime/src/capability/pending.rs` names the same 300 as `DEFAULT_REQUEST_TIMEOUT_SECS`. This task does not copy that store and does not add a second timeout number.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_lists_every_pending_request -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-pending-stub: the start of `get_capability_pending` returns `Ok` of `{"requests":[]}` before the caller check. Failed at `src/../standin-runtime/mod.rs:10526:9`: `a client is refused before the store is read`, left `Ok` of `{"requests":[]}`, right `Err((403, "This endpoint requires shell privileges"))`.

Old:

```text
    pub fn get_capability_pending(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
```

New:

```text
    pub fn get_capability_pending(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        return Ok(json!({ "requests": [] }));
        require_shell(caller)?;
```

F-standin-pending-all: the filter keeps every status, so a granted id is listed. Failed at `src/../standin-runtime/mod.rs:10631:9`: `a granted request leaves the shell pending list`, left `["req-a", "req-c", "req-b"]`, right `["req-a", "req-b"]`.

Old:

```text
            .filter(|request| request.status == RequestStatus::Pending)
```

New:

```text
            .filter(|_request| true)
```

F-standin-pending-order: the list keeps store order, so `req-b` comes before `req-a`. Failed at `src/../standin-runtime/mod.rs:10563:9`: `the shell pending list is req-a, req-c, req-b`, left `["req-b", "req-c", "req-a"]`, right `["req-a", "req-c", "req-b"]`.

Old:

```text
        listed.sort_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then(left.request_id.cmp(&right.request_id))
        });
        let requests = listed.into_iter().map(pending_entry).collect::<Vec<_>>();
```

New:

```text
        let requests = listed.into_iter().map(pending_entry).collect::<Vec<_>>();
```

F-standin-pending-clock: `expires_at` is `requested_at`, with no addition of `REQUEST_TIMEOUT_SECS`. Failed at `src/../standin-runtime/mod.rs:10472:9`: `req-a expires at requested_at plus REQUEST_TIMEOUT_SECS`, left `Some(0)`, right `Some(300)`.

Old:

```text
fn request_expires_at(requested_at: u64) -> u64 {
    requested_at.saturating_add(REQUEST_TIMEOUT_SECS)
}
```

New:

```text
fn request_expires_at(requested_at: u64) -> u64 {
    requested_at
}
```

F-standin-pending-session-only: the list sorts only by `session_id`, so `req-c` stays before `req-a`. Failed at `src/../standin-runtime/mod.rs:10564:9`: `the shell pending list is req-a, req-c, req-b`, left `["req-c", "req-a", "req-b"]`, right `["req-a", "req-c", "req-b"]`.

Old:

```text
        listed.sort_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then(left.request_id.cmp(&right.request_id))
        });
```

New:

```text
        listed.sort_by(|left, right| left.session_id.cmp(&right.session_id));
```

F-standin-pending-denied: the filter includes `Denied`, so `req-d` is listed. Failed at `src/../standin-runtime/mod.rs:10654:9`: `a denied request leaves the shell pending list`, left `["req-a", "req-d", "req-b"]`, right `["req-a", "req-b"]`.

Old:

```text
            .filter(|request| request.status == RequestStatus::Pending)
```

New:

```text
            .filter(|request| request.status != RequestStatus::Granted)
```

F-standin-pending-fields: `pending_entry` substitutes action, reason and resource for one another. Failed at `src/../standin-runtime/mod.rs:10455:9`: `req-a keeps its resource`, left `String("read")`, right `"localhost://Public/resident-instances/a.txt"`.

Old:

```text
        "resource": request.resource,
        "action": request.action,
        "reason": request.reason,
```

New:

```text
        "resource": request.action,
        "action": request.reason,
        "reason": request.resource,
```

F-standin-pending-wrap: `expires_at` uses `wrapping_add` in place of `saturating_add`. Failed at `src/../standin-runtime/mod.rs:10472:9`: `req-sat expires at requested_at plus REQUEST_TIMEOUT_SECS`, left `Some(289)`, right `Some(18446744073709551615)`.

Old:

```text
    requested_at.saturating_add(REQUEST_TIMEOUT_SECS)
```

New:

```text
    requested_at.wrapping_add(REQUEST_TIMEOUT_SECS)
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. `Cargo.toml` and `Cargo.lock` are unchanged. The forbidden `git diff` is empty. After the plants were restored, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` has no plant.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.47 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 306.23 seconds, inside the 600-second bound. Targets in order: lib 73 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.47 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_lists_every_pending_request -- --exact` exit 0, 1 passed and 0 failed, real 11.88 seconds.

Principles: `get_capability_pending` at `standin-runtime/mod.rs:372` reads the same `requests` store. `require_shell` at `:373` refuses a client with `This endpoint requires shell privileges` (`:1397`) before that read. `request_expires_at` at `:1367` is the one addition of `REQUEST_TIMEOUT_SECS`, using `saturating_add`. `pending_entry` at `:1371` copies `request_id`, `session_id`, `resource`, `action`, `reason` and `requested_at` from the request. The method is `&self`, so it does not grant, settle or call `expire_due`. `get_capability_requests` stays the per-session record. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.

### Supervisor gate and one rerun

The supervisor gate, `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`, exited 101. The only failure was `cleanup_census_refuses_each_leftover`. Its census line was `process leftover; processes:1 paths:["stdout-25"]`. That name is outside the named rerun list. The path matches `stdout-<digits>`. It does not include `host-process.lock` or `config.toml`. Census, the operator and the stand-in were left unchanged.

- Rerun: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.17 seconds. `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml` exit 0, real 278.67 seconds, inside the 600-second bound. Targets in order: lib 73 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after that rerun: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_lists_every_pending_request -- --exact` exit 0, 1 passed and 0 failed, real 0.10 seconds.

## 079 — Record an approved use on the one audit list

079: `record_use` appends one `capability_use` after `protected_write` or `protected_read` succeeds. `get_audit` answers `GET /api/audit`. A client is refused before that list is read. The list is newest first. `total_in_memory` counts every stored event before the type filter and before the limit. A refusal appends nothing. The lab event has no `token` key and no `token_id` key. The body has no `current_epoch` key. `standin_approved_use_is_on_the_audit_list` fails on each hand-run plant and passes when they are restored. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.

The spec check extends that test. It stores 1,001 events and asserts the default 100 and the maximum 1,000. It checks each refusal reason for both protected methods, and it checks that the stored bytes stay. It checks component-2's complete event and the `req-once` resource. The limit plant and the type plant are separate, and so are the two bound plants.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 9:

```text
9. Runtime dispatches an approved operation to the owning provider and records
   the result in the same audit path used for a human action.
```

This task is that record for a protected use. It is not a grant, and it does not mint a token.

`elastos/crates/elastos-runtime/src/primitives/audit.rs`, `AuditEvent::CapabilityUse` field names: `timestamp`, `token_id`, `capsule_id`, `resource`, `action`, `success`. The newest-first comments are `Returns the most recent limit events, newest first.` on `recent_events`, and `Returns the most recent events matching the filter, newest first.` on `recent_events_filtered`. `elastos/crates/elastos-server/src/api/handlers/capability.rs` says `List of audit events (newest first)`. The query names are `limit` (default 100, max 1000) and `type`. The handler body also has `current_epoch`. This stand-in does not copy that logger and does not write a file. The lab event therefore has no `token_id` and no `token` key. The lab body has no `current_epoch`.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_approved_use_is_on_the_audit_list -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-audit-stub: the start of `get_audit` returns `Ok` of `{"events":[],"total_in_memory":0}` before the caller check. Failed at `src/../standin-runtime/mod.rs:11041:9`: `a client is refused before the store is read`, left `Ok` of `{"events":[],"total_in_memory":0}`, right `Err((403, "This endpoint requires shell privileges"))`.

Old:

```text
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
```

New:

```text
    ) -> Result<Value, (u16, String)> {
        return Ok(json!({ "events": [], "total_in_memory": 0 }));
        require_shell(caller)?;
```

F-standin-audit-before: the start of `protected_write` calls `record_use` and then continues, so the missing-grant write is listed. Failed at `src/../standin-runtime/mod.rs:11066:9`: `an unknown grant appends nothing`, left `total_in_memory` 1 with `request_id` `req-missing`, right `{"events":[],"total_in_memory":0}`.

Old:

```text
    ) -> Result<String, (u16, String)> {
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

New:

```text
    ) -> Result<String, (u16, String)> {
        self.record_use(request_id, instance_id, uri, "write");
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

F-standin-audit-guest: `record_use` stores the guest uri. The read still uses the resolved uri. Failed at `src/../standin-runtime/mod.rs:10888:9`: `the approved write records the resolved uri`, left resource `localhost://UsersAI/self/journal`, right resource `localhost://UsersAI/763281cf1e57227a6b99d89d/journal`.

Old, the write call:

```text
        self.record_use(request_id, instance_id, &resolved, "write");
```

New, the write call:

```text
        self.record_use(request_id, instance_id, uri, "write");
```

Old, the read call:

```text
        self.record_use(request_id, instance_id, &resolved, "read");
```

New, the read call:

```text
        self.record_use(request_id, instance_id, uri, "read");
```

F-standin-audit-oldest: `get_audit` returns insertion order, so the write stays ahead of the later read. Failed at `src/../standin-runtime/mod.rs:10887:9`: `the later read is ahead of the earlier write`, left `request_id` `req-a` action `write`, right `request_id` `req-read` action `read`.

Old:

```text
            .iter()
            .rev()
            .filter(|event| match event_type {
```

New:

```text
            .iter()
            .filter(|event| match event_type {
```

F-standin-audit-clock: `record_use` stores `at` `0` for every event. Failed at `src/../standin-runtime/mod.rs:11216:9`: `the later write records the test instant`, left `0`, right `4`.

Old:

```text
            event_type: "capability_use",
            at: self.instant,
```

New:

```text
            event_type: "capability_use",
            at: 0,
```

F-standin-audit-limit: `get_audit` ignores `limit` and still filters `type`. Failed at `src/../standin-runtime/mod.rs:11241:9`: `limit 1 keeps one event`, left `Some(4)`, right `Some(1)`.

Old:

```text
                None => true,
            })
            .take(cap)
            .map(audit_entry)
```

New:

```text
                None => true,
            })
            .map(audit_entry)
```

F-standin-audit-type: `get_audit` ignores `event_type` and still applies `limit`. Failed at `src/../standin-runtime/mod.rs:11276:9`: `a capsule_launch filter keeps no capability_use event`, left the four stored `capability_use` events, right `[]`.

Old:

```text
            .filter(|event| match event_type {
                Some(wanted) => event.event_type == wanted,
                None => true,
            })
```

New:

```text
            .filter(|_event| true)
```

F-standin-audit-default: `limit: None` returns every stored event. Failed at `src/../standin-runtime/mod.rs:11923:9`: `the default limit keeps 100 events`, left `Some(1001)`, right `Some(100)`.

Old:

```text
            None => AUDIT_DEFAULT_LIMIT,
```

New:

```text
            None => self.audit.len(),
```

F-standin-audit-max: a limit above 1000 is not capped. Failed at `src/../standin-runtime/mod.rs:11939:9`: `a limit above 1000 keeps 1000 events`, left `Some(1001)`, right `Some(1000)`.

Old:

```text
            Some(n) => n.min(AUDIT_MAX_LIMIT),
```

New:

```text
            Some(n) => n,
```

F-standin-audit-read-refusal: the start of `protected_read` calls `record_use` and then continues, so the absent read is listed. Failed at `src/../standin-runtime/mod.rs:11165:9`: `an absent read appends nothing`, left `2`, right `1`.

Old:

```text
    ) -> Result<Vec<u8>, (u16, String)> {
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

New:

```text
    ) -> Result<Vec<u8>, (u16, String)> {
        self.record_use(request_id, instance_id, uri, "read");
        let resolved = self.resolve_protected_uri(instance_id, uri)?;
```

F-standin-audit-session: `record_use` stores `session_id` `component-1` for every event. Failed at `src/../standin-runtime/mod.rs:10888:9`: `component-2 records its own session and resource`, left `session_id` `component-1`, right `session_id` `component-2`.

Old:

```text
            event_type: "capability_use",
            at: self.instant,
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
```

New:

```text
            event_type: "capability_use",
            at: self.instant,
            request_id: request_id.to_owned(),
            session_id: "component-1".to_owned(),
            resource: resource.to_owned(),
```

F-standin-audit-resource: `record_use` stores the previous event's resource. Failed at `src/../standin-runtime/mod.rs:10893:9`: `the once use records its own resource`, left the journal uri, right `localhost://UsersAI/763281cf1e57227a6b99d89d/once`.

Old:

```text
    fn record_use(&mut self, request_id: &str, session_id: &str, resource: &str, action: &str) {
        self.audit.push(AuditUse {
```

New:

```text
    fn record_use(&mut self, request_id: &str, session_id: &str, resource: &str, action: &str) {
        let resource = self
            .audit
            .last()
            .map(|event| event.resource.clone())
            .unwrap_or_else(|| resource.to_owned());
        self.audit.push(AuditUse {
```

### Gates

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.27 seconds. `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 320.54 seconds, inside the 600-second bound. Targets in order: lib 74 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.27 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_approved_use_is_on_the_audit_list -- --exact` exit 0, 1 passed and 0 failed, real 0.28 seconds.

Principles: `record_use` at `standin-runtime/mod.rs:909` is the one append. `protected_write` calls it at `:872` after the bytes are stored. `protected_read` calls it at `:900` after the bytes are found. `get_audit` at `:932` is `&self`. `require_shell` at `:938` refuses a client with `This endpoint requires shell privileges` (`:1491`) before `self.audit.len()` at `:939`. The list walks newest first at `:947`. `total_in_memory` is the store length before `take` at `:952`. The event resource is the resolved uri at `:915`. The body keys are `events` and `total_in_memory` at `:955`. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.

## 080 — Hostcall returns a protected read or write

080: a `resource_invoke` on `localhost://Users/` or `localhost://UsersAI/` calls `protected_read` or `protected_write` through the one `bridge_envelope`. A write success is `{"stored":true}`. A read success is the stored text. The response has no token, no principal, and no resolved root. A method error keeps `code` `denied` and drops the numeric status. A resolved root in that reason is rewritten to the guest form. Stored text is returned unchanged, including when it contains a principal name. Bytes that are not UTF-8 are refused with `protected read is not utf-8`. Any other invoke still calls `authorise` and returns `data` null. The plants below fail the named test and pass when restored. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.

The spec check is applied. `wrong resource` can name a resolved root, so the hostcall redacts that reason. The privacy rule covers Runtime-supplied metadata, and approved stored text can contain `agent-ada`. `protected_read` returns bytes, and a JSON string needs text, so invalid UTF-8 has its own refusal. The main test also round-trips `localhost://Users/self`, refuses a missing, null, numeric, boolean, or array write body, and reads once through a `once` grant.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 10:

```text
10. The result returns to the Agent Host and Home without exposing provider
    credentials or broader authority.
```

This task is that return for a `Users/self` or `UsersAI/self` invoke. It is not a second hostcall.

`elastos/crates/elastos-guest/src/runtime.rs`, `RuntimeRequest::ResourceInvoke` fields: `uri`, `operation`, `body`, `token`.

### Plants

Each plant was applied alone. The planted crate compiled, and the named test failed on its assertion. The file was restored before the next plant. Restored, the tests pass. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

The command for the main-test plants was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_returns_the_protected_result -- --exact`.

F-standin-bridge-protected-skip: the Users arm calls `authorise` and returns `data` null, and does not call `protected_write`. Failed at `src/../standin-runtime/mod.rs:8633:9`: `an object write body is refused`, left `data` null with `type` `ok`, right the error `protected write body must be a string`.

Old:

```text
                if protected_invoke(uri) {
                    self.bridge_protected_invoke(request, capsule_id, token, uri)
                } else {
```

New:

```text
                if protected_invoke(uri) {
                    let invoke_caller = Caller::Client {
                        session_id: capsule_id,
                    };
                    match self.authorise(invoke_caller, token) {
                        Ok(()) => bridge_ok(Value::Null),
                        Err((_status, message)) => bridge_error(&message),
                    }
                } else {
```

F-standin-bridge-double-spend: the Users write arm calls `authorise` and then `protected_write`. Failed at `src/../standin-runtime/mod.rs:8611:9`: `the once write returns stored`, left `grant is not live: Exhausted`, right `{"stored":true}`.

Old:

```text
                let Some(text) = request.get("body").and_then(Value::as_str) else {
                    return bridge_error("protected write body must be a string");
                };
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
```

New:

```text
                let Some(text) = request.get("body").and_then(Value::as_str) else {
                    return bridge_error("protected write body must be a string");
                };
                let _ = self.authorise(
                    Caller::Client {
                        session_id: capsule_id,
                    },
                    token,
                );
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
```

F-standin-bridge-returns-root: the write success puts the resolved uri in `response.data`. Failed at `src/../standin-runtime/mod.rs:8605:9`: `the approved write returns stored`, left `localhost://UsersAI/763281cf1e57227a6b99d89d/journal`, right `{"stored":true}`.

Old:

```text
                    Ok(_resolved) => bridge_ok(json!({ "stored": true })),
```

New:

```text
                    Ok(resolved) => bridge_ok(Value::String(resolved)),
```

F-standin-bridge-principal-caller: the Users arm uses `principal.unwrap_or(capsule_id)` as the instance id. Failed at `src/../standin-runtime/mod.rs:8610:9`: `the approved write returns stored`, left `unknown instance: agent-ada`, right `{"stored":true}`.

Old:

```text
                    self.bridge_protected_invoke(request, capsule_id, token, uri)
```

New:

```text
                    self.bridge_protected_invoke(
                        request,
                        principal.unwrap_or(capsule_id),
                        token,
                        uri,
                    )
```

F-standin-bridge-all-protected: every `resource_invoke` calls `protected_read`, including the Public uri. Failed at `src/../standin-runtime/mod.rs:8625:9`: `an object write body is refused`, left `wrong action: expected write, got read`, right `protected write body must be a string`.

Old:

```text
            "resource_invoke" => {
                let token = invoke_token(request)?;
                let uri = invoke_uri(request);
                if protected_invoke(uri) {
                    self.bridge_protected_invoke(request, capsule_id, token, uri)
                } else {
                    let invoke_caller = Caller::Client {
                        session_id: capsule_id,
                    };
                    match self.authorise(invoke_caller, token) {
                        Ok(()) => bridge_ok(Value::Null),
                        Err((_status, message)) => bridge_error(&message),
                    }
                }
            }
```

New:

```text
            "resource_invoke" => {
                let token = invoke_token(request)?;
                let uri = invoke_uri(request);
                match self.protected_read(capsule_id, token, uri) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => bridge_ok(Value::String(text)),
                        Err(_bytes) => bridge_error("protected read is not utf-8"),
                    },
                    Err((_status, message)) => {
                        bridge_error(&self.redact_protected_reason(capsule_id, &message))
                    }
                }
            }
```

F-standin-bridge-users-only: `protected_invoke` matches only `localhost://UsersAI/`. Failed at `src/../standin-runtime/mod.rs:8605:9`: `the Users write returns stored`, left `data` null, right `{"stored":true}`.

Old:

```text
fn protected_invoke(uri: &str) -> bool {
    uri.starts_with("localhost://Users/") || uri.starts_with("localhost://UsersAI/")
}
```

New:

```text
fn protected_invoke(uri: &str) -> bool {
    uri.starts_with("localhost://UsersAI/")
}
```

F-standin-bridge-body-bypass: a missing, null, numeric, boolean, or array write body is stored as an empty string. An object body stays refused. Failed at `src/../standin-runtime/mod.rs:8631:9`: `a missing write body is refused`, left `{"stored":true}`, right `protected write body must be a string`.

Old:

```text
                let Some(text) = request.get("body").and_then(Value::as_str) else {
                    return bridge_error("protected write body must be a string");
                };
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
```

New:

```text
                let text = match request.get("body") {
                    Some(Value::String(text)) => text.clone(),
                    Some(Value::Object(_)) => {
                        return bridge_error("protected write body must be a string");
                    }
                    _ => String::new(),
                };
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
```

F-standin-bridge-read-authorise: the Users read arm calls `authorise` and then `protected_read`. Failed at `src/../standin-runtime/mod.rs:8613:9`: `the once read returns the stored text`, left `grant is not live: Exhausted`, right `journal-v1`.

Old:

```text
            "read" => match self.protected_read(capsule_id, token, uri) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => bridge_ok(Value::String(text)),
                    Err(_bytes) => bridge_error("protected read is not utf-8"),
                },
                Err((_status, message)) => {
                    bridge_error(&self.redact_protected_reason(capsule_id, &message))
                }
            },
```

New:

```text
            "read" => {
                let _ = self.authorise(
                    Caller::Client {
                        session_id: capsule_id,
                    },
                    token,
                );
                match self.protected_read(capsule_id, token, uri) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => bridge_ok(Value::String(text)),
                        Err(_bytes) => bridge_error("protected read is not utf-8"),
                    },
                    Err((_status, message)) => {
                        bridge_error(&self.redact_protected_reason(capsule_id, &message))
                    }
                }
            }
```

F-standin-bridge-read-body: a read whose body is not an object is refused. Failed at `src/../standin-runtime/mod.rs:8610:9`: `a null read body is ignored`, left `protected write body must be a string`, right `journal-v1`.

Old: the `read` arm above.

New:

```text
            "read" => match request.get("body") {
                Some(body) if !body.is_object() => {
                    bridge_error("protected write body must be a string")
                }
                _ => match self.protected_read(capsule_id, token, uri) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => bridge_ok(Value::String(text)),
                        Err(_bytes) => bridge_error("protected read is not utf-8"),
                    },
                    Err((_status, message)) => {
                        bridge_error(&self.redact_protected_reason(capsule_id, &message))
                    }
                },
            },
```

F-standin-bridge-operation: an operation other than `read` or `write` calls `protected_write` when the body is a string. Failed at `src/../standin-runtime/mod.rs:8637:9`: `list is not a protected operation`, left `{"stored":true}`, right `protected operation is read or write`.

Old:

```text
            _ => bridge_error("protected operation is read or write"),
```

New:

```text
            _ => {
                let Some(text) = request.get("body").and_then(Value::as_str) else {
                    return bridge_error("protected operation is read or write");
                };
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
                    Ok(_resolved) => bridge_ok(json!({ "stored": true })),
                    Err((_status, message)) => {
                        bridge_error(&self.redact_protected_reason(capsule_id, &message))
                    }
                }
            }
```

F-standin-bridge-verbatim: the write error is forwarded unchanged. Command: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_redacts_protected_errors -- --exact`. Failed at `src/../standin-runtime/mod.rs:8625:9`: `the hostcall redacts the resolved Users root`, left `wrong resource: expected localhost://Users/763281cf1e57227a6b99d89d/journal, got localhost://Users/self/other`, right the same sentence with `localhost://Users/self/journal`.

Old:

```text
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
                    Ok(_resolved) => bridge_ok(json!({ "stored": true })),
                    Err((_status, message)) => {
                        bridge_error(&self.redact_protected_reason(capsule_id, &message))
                    }
                }
```

New:

```text
                match self.protected_write(capsule_id, token, uri, text.as_bytes()) {
                    Ok(_resolved) => bridge_ok(json!({ "stored": true })),
                    Err((_status, message)) => bridge_error(&message),
                }
```

F-standin-bridge-payload: the read success replaces `agent-ada` with `capsule`. Command: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_preserves_payload_text -- --exact`. Failed at `src/../standin-runtime/mod.rs:8605:9`: `the payload read returns the stored text`, left `capsule 763281cf1e57227a6b99d89d`, right `agent-ada 763281cf1e57227a6b99d89d`.

Old:

```text
                    Ok(text) => bridge_ok(Value::String(text)),
```

New:

```text
                    Ok(text) => bridge_ok(Value::String(text.replace("agent-ada", "capsule"))),
```

F-standin-bridge-lossy: invalid UTF-8 is decoded with `from_utf8_lossy` and returned as success. Command: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_refuses_invalid_utf8 -- --exact`. Failed at `src/../standin-runtime/mod.rs:8626:9`: `invalid utf-8 is refused`, left `type` `ok` with the replacement characters, right `protected read is not utf-8`.

Old:

```text
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => bridge_ok(Value::String(text)),
                    Err(_bytes) => bridge_error("protected read is not utf-8"),
                },
```

New:

```text
                Ok(bytes) => {
                    bridge_ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
                },
```

### Gates

`RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 284.92 seconds, inside the 600-second bound. Targets in order: lib 78 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0. No census line and no listed flaky test failed, so the single-rerun rule did not apply.
- Proof after the plants were restored: `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` exit 0, real 0.25 seconds; `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_returns_the_protected_result -- --exact` exit 0, 1 passed and 0 failed, real 9.94 seconds.

Principles: `protected_invoke` at `standin-runtime/mod.rs:1951` selects the guest uri. `bridge_envelope` at `:502` calls `bridge_protected_invoke` for that uri and does not call `authorise` there. The other invoke arm still calls `authorise` at `:507` and returns `data` null at `:508`. `bridge_protected_invoke` at `:541` calls `protected_read` or `protected_write` with `capsule_id`. `principal` is unused at `:481`. `protected_write` still calls `authorise_presented` at `:931`. `redact_protected_reason` at `:569` rewrites a resolved root through `resolve_protected_uri`. A write body that is not a string is `protected write body must be a string` at `:552`. Any other operation is `protected operation is read or write` at `:561`. Invalid UTF-8 is `protected read is not utf-8` at `:544`. A PASS gives the Runtime no A15 credit. `session_id` still equals the instance id.


### Ownership repair — protected error roots

The hostcall uses one `redact_protected_reason` for read and write errors. It now replaces the root segment of every `localhost://Users/` or `localhost://UsersAI/` URI in the reason with `self`, independent of the caller. The mismatch reason and guest path remain. Approved stored text follows the existing success path and stays unchanged.

`standin_hostcall_redacts_protected_errors` keeps its existing assertions and adds 16 mismatch cases: Ada's and Bob's roots, both protected namespaces, read and write, and a root with or without a child path. Each grant belongs to Ada's instance. Each case asserts the exact redacted reason, checks both principals' privacy, and checks that the once grant stays live. The existing empty-store assertion covers all cases. `standin_hostcall_preserves_payload_text` now round-trips both principal names, both digests, and both namespaces' resolved URIs as approved text; all its assertions remain.

Before the helper repair, the extended error test compiled and failed at `src/../standin-runtime/mod.rs:8627:9`, with `the stand-in did the work: the hostcall redacts any owner's Users root on read`. The returned expected-resource field still held Bob's digest; the assertion required `localhost://Users/self`. Command: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_redacts_protected_errors -- --exact`. Exit 101, real 15.27 seconds.

F-standin-bridge-public-protected changes only Public dispatch. Protected requests keep their existing dispatch, so the test reaches the Public assertion. This supplements F-standin-bridge-all-protected above.

Exact old bytes, including the trailing newline:

```text
                if protected_invoke(uri) {
```

Exact new bytes, including the trailing newline:

```text
                if protected_invoke(uri) || uri.starts_with("localhost://Public/") {
```

Command: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_returns_the_protected_result -- --exact`. The planted crate compiled. Exit 101, real 6.22 seconds. The assertion at `src/../standin-runtime/mod.rs:8614:9` failed with `the stand-in did the work: the public invoke returns data null`: actual `id` 8 with `type` `error`, `code` `denied`, and message `protected storage needs a Users/self or UsersAI/self resource`; expected `id` 8 with `type` `ok` and `data` null. The source bytes were restored in `finally` and checked for exact identity.

Repair checks use `RUST_TEST_THREADS=2`, `CARGO_INCREMENTAL=0`, and `CARGO_NET_OFFLINE=true`. Cargo outputs stay under the lane's existing `target/`, with `CARGO_BUILD_BUILD_DIR` set to `target/host` and `CARGO_TARGET_DIR` set to `target`.

- After restoration, `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- After restoration, `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::`: exit 0, 78 passed, real 6.28 seconds. This includes all four hostcall tests.
- Exact restored proof: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_returns_the_protected_result -- --exact`: exit 0, 1 passed, real 0.07 seconds.

Source hashes before and after the repair confirm that `bridge_envelope`, `protected_write`, `protected_read`, `authorise`, `authorise_presented`, `bind_verified_principal`, `resolve_protected_uri`, `record_use`, and `get_audit` are unchanged. The Public invoke arm remains within the unchanged `bridge_envelope`. The repair changes only `standin-runtime/mod.rs` and this record. Full-suite verification remains with the supervisor: this repair turn forbids Git commands, and the integration tests invoke Git through their receipt and source checks. The supervisor's fresh review remains required.

## 081 — Shell grant, deny and revoke join the audit list

081: `record_use` is the only append. A shell grant, deny, or revoke calls it once after that decision succeeds. A refusal appends nothing. `get_audit_types` answers `GET /api/audit/types` with `capability_denied`, `capability_grant`, `capability_revoke` and `capability_use`. `standin_shell_decisions_join_the_audit_list` fails on each hand-run plant and passes when they are restored. A PASS gives the Runtime no A15 credit and no A6 credit. `session_id` still equals the instance id. A stop's revoke stays unwritten.

### Quotes from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 9:

```text
Runtime dispatches an approved operation to the owning provider and records
the result in the same audit path used for a human action.
```

This task is that record for a shell grant, a shell deny, and a shell revoke. It is not a new list.

`elastos/crates/elastos-runtime/src/primitives/audit.rs`, `event_type_name`:

```text
AuditEvent::CapabilityGrant { .. } => "capability_grant",
AuditEvent::CapabilityDenied { .. } => "capability_denied",
AuditEvent::CapabilityRevoke { .. } => "capability_revoke",
```

`elastos/crates/elastos-server/src/api/handlers/capability.rs`, `get_audit_event_types`, returns `event_types`. The three strings above are the shell decisions. This stand-in also names the existing `capability_use`. It does not copy the handler's full type list, a token, or an epoch.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_decisions_join_the_audit_list -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-audit-decision-stub: the start of `post_capability_grant` returns Ok of `{"success": true}` before the writer and before `record_use`. Failed at `src/../standin-runtime/mod.rs:13198:9`: `a client grant is refused before the body is read`, left `Ok` of `{"success": true}`, right `Err((403, "This endpoint requires shell privileges"))`.

Old:

```text
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

New:

```text
        return Ok(json!({ "success": true }));
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

F-standin-audit-decision-before: after the shell check and the body parse, `post_capability_grant` calls `record_use` and then continues, so the unknown id is listed. Failed at `src/../standin-runtime/mod.rs:13392:9`: `an unknown grant appends nothing`, left one event with `request_id` `missing`, right `{"events":[],"total_in_memory":0}`.

Old:

```text
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

New:

```text
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
        self.record_use(
            "capability_grant",
            true,
            request_id,
            "component-1",
            "localhost://Public/resident-instances/shared.txt",
            "read",
        );
```

F-standin-audit-grant-as-use: the grant success appends `capability_use`. Failed at `src/../standin-runtime/mod.rs:11183:9`: `capability_grant req-c`, left `type` `capability_use`, right `type` `capability_grant`.

Old:

```text
        self.record_use(
            "capability_grant",
            true,
            &request_id,
            &session_id,
            &resource,
            &action,
        );
```

New:

```text
        self.record_use(
            "capability_use",
            true,
            &request_id,
            &session_id,
            &resource,
            &action,
        );
```

F-standin-audit-revoke-skip: `delete_capability` does not call `record_use`. Failed at `src/../standin-runtime/mod.rs:13689:9`: `the revoke appends one event`, left `4`, right `5`.

Old:

```text
        self.revoke_grant(request_id);
        self.record_use(
            "capability_revoke",
            true,
            request_id,
            &session_id,
            &resource,
            &action,
        );
```

New:

```text
        self.revoke_grant(request_id);
```

F-standin-audit-revoke-all-one: `post_capability_revoke_all` appends one `capability_revoke` and returns, so `req-b` and `req-orphan` are absent. Failed at `src/../standin-runtime/mod.rs:11184:9`: `capability_revoke req-orphan`, left `request_id` `req-c`, right `request_id` `req-orphan`.

Old:

```text
        for (session_id, request_id, resource, action) in &snapshot {
            self.record_use(
                "capability_revoke",
                true,
                request_id,
                session_id,
                resource,
                action,
            );
        }
```

New:

```text
        if let Some((session_id, request_id, resource, action)) = snapshot.first() {
            self.record_use(
                "capability_revoke",
                true,
                request_id,
                session_id,
                resource,
                action,
            );
        }
        return Ok(json!({ "success": true, "reason": reason }));
```

F-standin-audit-types-stored: `get_audit_types` returns only types present in the store. Failed at `src/../standin-runtime/mod.rs:13166:9`: `the shell type list names the four audit types`, left `event_types` `[]`, right the four names.

Old:

```text
        require_shell(caller)?;
        Ok(json!({
            "event_types": [
                "capability_denied",
                "capability_grant",
                "capability_revoke",
                "capability_use",
            ],
        }))
```

New:

```text
        require_shell(caller)?;
        let mut names = self
            .audit
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        Ok(json!({ "event_types": names }))
```

F-standin-audit-client-grant: the client branch of `post_capability_grant` appends and then returns 403. Failed at `src/../standin-runtime/mod.rs:13208:9`: `a client grant is refused before the body is read appends nothing`, left `1`, right `0`.

Old:

```text
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

New:

```text
        if let Caller::Client { .. } = caller {
            self.record_use(
                "capability_grant",
                true,
                "client",
                "component-1",
                "localhost://Public/resident-instances/shared.txt",
                "read",
            );
            return Err((403, "This endpoint requires shell privileges".to_owned()));
        }
        require_shell(caller)?;
        let (request_id, duration, rationale) = grant_body(body)?;
```

F-standin-audit-body-grant: a malformed grant body appends and then returns the body error. Failed at `src/../standin-runtime/mod.rs:13242:9`: `a grant body that is not an object is refused appends nothing`, left `1`, right `0`.

Old:

```text
        let (request_id, duration, rationale) = grant_body(body)?;
```

New:

```text
        let (request_id, duration, rationale) = match grant_body(body) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.record_use(
                    "capability_grant",
                    false,
                    "bad",
                    "component-1",
                    "localhost://Public/resident-instances/shared.txt",
                    "read",
                );
                return Err(error);
            }
        };
```

F-standin-audit-pending-grant: a request that is not pending appends and then returns. Failed at `src/../standin-runtime/mod.rs:13478:9`: `a second grant of req-a is refused appends nothing`, left `4`, right `3`.

Old:

```text
        if request.status != RequestStatus::Pending {
            return Err((400, format!("request is not pending: {request_id}")));
        }
        let request_id = request.request_id.clone();
```

New:

```text
        let not_pending = request.status != RequestStatus::Pending;
        if not_pending {
            self.record_use(
                "capability_grant",
                false,
                request_id,
                "component-1",
                "localhost://Public/resident-instances/shared.txt",
                "read",
            );
            return Err((400, format!("request is not pending: {request_id}")));
        }
        let request_id = request.request_id.clone();
```

F-standin-audit-deny-skip: `post_capability_deny` does not call `record_use`. Failed at `src/../standin-runtime/mod.rs:13545:9`: `the deny appends one event`, left `3`, right `4`.

Old:

```text
        self.record_use(
            "capability_denied",
            false,
            request_id,
            &session_id,
            &resource,
            &action,
        );
```

New: that call is removed.

F-standin-audit-types-shell: `get_audit_types` returns the type list before the shell check. Failed at `src/../standin-runtime/mod.rs:13171:9`: `a client is refused before the type list is built`, left `Ok` of the four names, right `Err((403, "This endpoint requires shell privileges"))`.

Old:

```text
        require_shell(caller)?;
```

New:

```text
        let _ = caller;
```

F-standin-audit-revoke-excluded: the revoke-all snapshot keeps every grant and every pending request. Failed at `src/../standin-runtime/mod.rs:11261:9`: `req-spent adds no audit event`.

Old:

```text
            .filter(|grant| is_live(grant.life))
            .map(|grant| {
                (
                    grant.session_id.clone(),
                    grant.request_id.clone(),
                    grant.resource.clone(),
                    grant.action.clone(),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
```

New:

```text
            .filter(|_| true)
            .map(|grant| {
                (
                    grant.session_id.clone(),
                    grant.request_id.clone(),
                    grant.resource.clone(),
                    grant.action.clone(),
                )
            })
            .collect::<Vec<_>>();
        for request in self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
        {
            snapshot.push((
                request.session_id.clone(),
                request.request_id.clone(),
                request.resource.clone(),
                request.action.clone(),
            ));
        }
        snapshot.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
```

F-standin-audit-revoke-empty: an empty Live snapshot appends one `capability_revoke`. Failed at `src/../standin-runtime/mod.rs:13360:9`: `a revoke-all with no Live grant appends nothing`, left `1`, right `0`.

Old:

```text
        snapshot.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
```

New:

```text
        snapshot.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        if snapshot.is_empty() {
            self.record_use(
                "capability_revoke",
                true,
                "empty",
                "component-1",
                "localhost://Public/resident-instances/shared.txt",
                "read",
            );
        }
```

F-standin-audit-field: the grant event stores resource `localhost://Public/resident-instances/swapped.txt`. Failed at `src/../standin-runtime/mod.rs:11183:9`: `capability_grant req-c`, left that swapped resource, right `localhost://Public/resident-instances/shared.txt`.

Old:

```text
        self.record_use(
            "capability_grant",
            true,
            &request_id,
            &session_id,
            &resource,
            &action,
        );
```

New:

```text
        self.record_use(
            "capability_grant",
            true,
            &request_id,
            &session_id,
            "localhost://Public/resident-instances/swapped.txt",
            &action,
        );
```

F-standin-audit-token: `audit_entry` adds `reason`, `token` and `current_epoch`. Failed at `src/../standin-runtime/mod.rs:2124:9`: `capability_grant req-c has type, at, request_id, session_id, resource, action and success`, left those three extra keys, right the seven names.

Old:

```text
        "success": event.success,
    })
```

New:

```text
        "success": event.success,
        "reason": "",
        "token": "",
        "current_epoch": 0,
    })
```

F-standin-audit-separate-list: `record_use` returns before the append when the type is not `capability_use`, so shell decisions stay off the list. Failed at `src/../standin-runtime/mod.rs:13439:9`: `three grants append three events`, left `0`, right `3`.

Old:

```text
        self.audit.push(AuditUse {
```

New:

```text
        if event_type != "capability_use" {
            return;
        }
        self.audit.push(AuditUse {
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 262.46 seconds, inside the 600-second bound. Targets: lib 79 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_shell_decisions_join_the_audit_list -- --exact`: exit 0, 1 passed, real 0.11 seconds.

## 084

084: `revoke_live` appends one `capability_revoke` through `record_use` for each `Live` grant it drops, sorted by `request_id`. A shell revoke still appends from its own route. A pending settlement appends nothing. `standin_stop_revoke_joins_the_audit_list` fails on each hand-run plant and passes when they are restored. A PASS gives the Runtime no A15 credit and no A6 credit. `session_id` still equals the instance id.

### Quote from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Request flow, step 9: "Runtime dispatches an approved operation to the owning provider and records the result in the same audit path used for a human action."

This task is that record for the grants `revoke_live` drops. It is not a new list and not a second revoke.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_stop_revoke_joins_the_audit_list -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-stop-audit-skip: `revoke_live` sets `Revoked` and does not call `record_use`. Failed at `src/../standin-runtime/mod.rs:14500:9`: `the stop appends one event per live grant`, left `0`, right `2`. Real 1.62 seconds.

Old:

```text
        for (request_id, _, _) in &dropped {
            self.revoke_grant(request_id);
        }
        for (request_id, resource, action) in &dropped {
            self.record_use(
                "capability_revoke",
                true,
                request_id,
                session_id,
                resource,
                action,
            );
        }
```

New:

```text
        for (request_id, _, _) in &dropped {
            self.revoke_grant(request_id);
        }
```

F-standin-stop-audit-as-use: the stop appends `capability_use`. Failed at `src/../standin-runtime/mod.rs:11214:9`: `the stop revoke of req-b`, left `type` `capability_use`, right `type` `capability_revoke`. Real 1.76 seconds.

Old:

```text
        for (request_id, resource, action) in &dropped {
            self.record_use(
                "capability_revoke",
```

New:

```text
        for (request_id, resource, action) in &dropped {
            self.record_use(
                "capability_use",
```

F-standin-stop-audit-sibling: `revoke_live` appends one event for every session's `Live` grant. Failed at `src/../standin-runtime/mod.rs:14510:9`: `the stop appends one event per live grant`, left `3`, right `2`. Real 1.54 seconds.

Old:

```text
.filter(|grant| grant.session_id == session_id && is_live(grant.life))
```

New:

```text
.filter(|grant| is_live(grant.life))
```

F-standin-stop-audit-pending: `settle_pending` also appends a `capability_revoke` for each pending request. Failed at `src/../standin-runtime/mod.rs:14518:9`: `the stop appends one event per live grant`, left `3`, right `2`. Real 1.82 seconds.

Old:

```text
        for request_id in pending {
            self.settle_record(&request_id, RequestStatus::Denied, cause, "runtime");
        }
```

New:

```text
        for request_id in pending {
            self.settle_record(&request_id, RequestStatus::Denied, cause, "runtime");
            self.record_use(
                "capability_revoke",
                true,
                &request_id,
                session_id,
                "",
                "",
            );
        }
```

F-standin-stop-audit-not-live: `revoke_live` also appends an `Exhausted`, `Revoked` or `Expired` grant of that session. Failed at `src/../standin-runtime/mod.rs:14510:9`: `the stop appends one event per live grant`, left `5`, right `2`. Real 1.54 seconds.

Old:

```text
.filter(|grant| grant.session_id == session_id && is_live(grant.life))
```

New:

```text
.filter(|grant| grant.session_id == session_id)
```

F-standin-stop-audit-request: `revoke_live` rewrites that session's request `resource` while it appends. Failed at `src/../standin-runtime/mod.rs:14600:9`: `the granted request record is unchanged`, left resource `changed`, right `localhost://Public/resident-instances/kept.txt`. Real 1.81 seconds.

Old:

```text
        for (request_id, _, _) in &dropped {
            self.revoke_grant(request_id);
        }
        for (request_id, resource, action) in &dropped {
```

New:

```text
        for (request_id, _, _) in &dropped {
            self.revoke_grant(request_id);
        }
        for request in &mut self.requests {
            if request.session_id == session_id {
                request.resource = "changed".to_owned();
            }
        }
        for (request_id, resource, action) in &dropped {
```

F-standin-stop-audit-rewrite: a refused second stop rewrites the stored events to `capability_use` and leaves the count at 2. Failed at `src/../standin-runtime/mod.rs:14636:9`: `a second stop leaves the audit list unchanged`, left both events `capability_use` with `total_in_memory` 2, right both events `capability_revoke` with `total_in_memory` 2. Real 1.54 seconds.

Old:

```text
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
        let session_id = self.instances[index].id.clone();
```

New:

```text
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            for event in &mut self.audit {
                event.event_type = "capability_use";
            }
            return Err(not_live(phase));
        }
        let session_id = self.instances[index].id.clone();
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 247.84 seconds, inside the 600-second bound. Targets: lib 80 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_stop_revoke_joins_the_audit_list -- --exact`: exit 0, 1 passed, real 1.54 seconds.

## 089

089: `start_provider` is the one lab launch seam. A caller passes the confinement profile path it already wrote. Started means that binary answered `init` with `status` `ok`, and the return owns the live child. Refused leaves no child. `ThrowawayHome::spawn` stays the only spawn; bounded stdin is an argument, and null stdin stays the default for every existing launch. A PASS gives the Runtime no C0 credit and no B3 credit.

### Quote from the contract (read only)

`docs/AGENT_ARCHITECTURE.md`, Runtime and provider architecture: "Runtime verifies the principal and session, enforces capabilities, owns lifecycle and audit, and routes the operation." Effect providers "do not decide that an unverified caller is authorized."

This task is the lab launch under a profile the caller already wrote. It does not mint a grant. `#309 at 513988ebd names no provider-launch ask; routed to Flint`.

### Plants

Each plant was applied alone, then restored before the next. The planted crate compiled. The named test failed on its assertion. Restored, it passes. No `falsifiers.json` id. `git diff -- lab/agent-conformance/standin-runtime/mod.rs` after restore shows no plant.

The four required plants used `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch -- --nocapture`. The extra plants used that command with the named test before `--`.

F-shared-launch-drop-profile: the spawn arguments omit `-f` and the profile path. Named test `standin_provider_launch_starts_under_caller_profile` panicked at `tests/provider_launch.rs:164:10`, `.expect("the caller profile starts the provider")`. Real 2.32 seconds. The same plant also failed `standin_provider_launch_refuses_stdin_past_its_limit` at `tests/provider_launch.rs:513:10` and `standin_provider_launch_uses_supplied_profile` at `tests/provider_launch.rs:431:5`.

Old:

```text
    arguments.push("-f".to_string());
    arguments.push(profile_text.to_string());
```

New: those two lines deleted.

F-shared-launch-wrong-profile: the restrictive profile is replaced by the committed oracle path. Named test `standin_provider_launch_uses_supplied_profile` panicked at `tests/provider_launch.rs:132:18`, `Ok(_) => panic!("the launch must be refused")`. Real 2.91 seconds.

Old:

```text
    arguments.push(profile_text.to_string());
```

New:

```text
    arguments.push(concat!(env!("CARGO_MANIFEST_DIR"), "/../../capsules/wallet-provider/confine.sb").to_string());
```

F-shared-launch-bare: the binary is started with no confinement tool. Named tests: `standin_provider_launch_starts_under_caller_profile` panicked at `tests/provider_launch.rs:213:5`, `assert_eq!(denied["status"], "error", "outside init: {denied}")`, left `String("ok")`, right `"error"`. `standin_provider_launch_uses_supplied_profile` panicked at `tests/provider_launch.rs:132:18`, `Ok(_) => panic!("the launch must be refused")`. Real 2.73 seconds. A later capture of the same plant confirmed the outside-init left/right values, then restored the file.

Old:

```text
    let program = tool_path;
    let arg_refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
```

New:

```text
    let program = binary.as_path();
    let arg_refs: Vec<&str> = Vec::new();
```

F-shared-launch-stub: the seam returns Started before `init` has answered `ok`. Named test `standin_provider_launch_starts_under_caller_profile` panicked at `tests/provider_launch.rs:188:5`, `wallet.is_dir() && status["data"]["storage_configured"] == true`. Real 2.52 seconds. The same plant also failed `standin_provider_launch_uses_supplied_profile` at `tests/provider_launch.rs:132:18`. Round 3 refreshed the old bytes to the current init exchange and re-ran the plant. See Round 3 below.

Old:

```text
    let init = exchange(&mut child, &init_request)
        .and_then(|init| {
            if init.get("status").and_then(Value::as_str) == Some("ok") {
                Ok(init)
            } else {
                Err(format!("init answered {init}"))
            }
        })
        .map_err(|reason| {
            provider_refusal(&mut child, format!("{name} start is refused: {reason}"))
        })?;
```

New:

```text
    let init = json!({"status": "ok", "data": {"storage_configured": true}});
```

F-shared-launch-primitive: the missing-primitive arm of `host_refusal` is deleted. Named test `standin_provider_launch_refuses_unconfined_host` panicked at `tests/provider_launch.rs:330:9`, `assert_eq!(reason, expected)`. Real 1.23 seconds.

Old:

```text
    if let Some(primitive) = host.unavailable {
        let reason = primitive.design_refusal();
        return Err(format!("{name} start on {} is refused: {reason}", host.os));
    }
```

New: that block deleted.

F-shared-launch-linux-lab: the Linux sentence says the lab enforces Linux. Same test, same assertion, `tests/provider_launch.rs:330:9`. Real 1.40 seconds.

Old:

```text
linux is designed, not enforced, in this lab
```

New:

```text
linux is designed and enforced, in this lab
```

F-shared-launch-unnamed-os: the unsupported-OS reason drops the reported OS name. Same test, same assertion, `tests/provider_launch.rs:330:9`. Real 1.39 seconds.

Old:

```text
        format!(
            "{} has no confinement design, and the lab stand-in applies confinement only on \
             {confined_os}",
            host.os
        )
```

New:

```text
        format!(
            "a host has no confinement design, and the lab stand-in applies confinement only on \
             {confined_os}"
        )
```

F-shared-launch-absent-tool: the absent-tool check is deleted. Same test panicked at `tests/provider_launch.rs:334:5`, the absent-tool `assert_eq!`. Real 1.54 seconds.

Old:

```text
    if !tool_path.is_file() {
        return Err(format!(
            "{name} start on {os} is refused: the confinement tool {} is absent",
            tool_path.display()
        ));
    }
```

New: that block deleted.

F-shared-launch-wrong-tool: the not-that-tool check is deleted. Same test panicked at `tests/provider_launch.rs:350:5`, the `/bin/echo` `assert_eq!`. Real 1.51 seconds.

Old:

```text
    if tool_path != Path::new(SANDBOX_EXEC) {
        return Err(format!(
            "{name} start on {os} is refused: the confinement tool {} is not {SANDBOX_EXEC}, \
             which is the one the stand-in runs",
            tool_path.display()
        ));
    }
```

New: that block deleted.

F-shared-launch-binary-file: the binary-is-a-file check is deleted. Same test panicked at `tests/provider_launch.rs:356:5`, the missing-binary `assert_eq!`. Real 1.65 seconds.

Old:

```text
    if !binary_path.is_file() {
        return Err(format!(
            "{name} start is refused: the provider binary {} is not a file",
            binary_path.display()
        ));
    }
```

New: that block deleted.

F-shared-launch-profile-file: the profile-is-a-file check is deleted. Named test `standin_provider_launch_uses_supplied_profile` panicked at `tests/provider_launch.rs:410:5`, `missing_reason.contains("is not a file")`. Real 1.83 seconds.

Old:

```text
    if !profile_path.is_file() {
        return Err(format!(
            "{name} start is refused: the confinement profile {} is not a file",
            profile_path.display()
        ));
    }
```

New: that block deleted.

F-shared-launch-unknown-name: an unknown name uses the wallet storage layout. Named test `standin_provider_launch_refuses_an_unknown_provider_name` panicked at `tests/provider_launch.rs:487:5`, the layout-sentence `assert_eq!`. Real 1.54 seconds.

Old:

```text
        other => Err(format!(
            "the stand-in serves only {DID_PROVIDER} and {WALLET_PROVIDER}, so {other} has no \
             storage root layout"
        )),
```

New:

```text
        other => Ok(base.join("ElastOS").join("SystemServices").join("Wallet")),
```

F-shared-launch-stdin: `write_bounded` no longer refuses a write past the limit. Named test `standin_provider_launch_refuses_stdin_past_its_limit` panicked at `tests/provider_launch.rs:517:10`, `.expect_err("a request past the stdin limit is refused")`. Real 2.31 seconds.

Old:

```text
        if next > self.spawned.stdin_limit {
            return Err("stdin exceeds its byte limit");
        }
```

New: that block deleted.

F-shared-launch-response-deadline: `read_line_within` no longer refuses at the deadline. Named test `standin_provider_launch_refuses_a_response_past_its_deadline` panicked at `tests/provider_launch.rs:547:5`, `assert_eq!(err, "provider response exceeded its deadline")`. Real 3.77 seconds.

Old:

```text
            if started.elapsed() >= deadline {
                return Err("provider response exceeded its deadline");
            }
```

New: that block deleted.

F-shared-launch-exit-deadline: `wait_for_exit_within` no longer refuses at the deadline. Named test `standin_provider_launch_refuses_an_exit_past_its_deadline` panicked at `tests/provider_launch.rs:572:10`, `.expect_err("a child that stays up is refused at the exit deadline")`. Real 3.44 seconds. Round 3 refreshed the old bytes to the current `kill_group(self.home)?` check and re-ran the plant. See Round 3 below.

Old:

```text
                    if started.elapsed() >= deadline {
                        self.kill_group(self.home)?;
                        self.stopped = true;
                        return Err("provider exit exceeded its deadline");
                    }
```

New: that block deleted.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The wallet-provider binary was built once under `lab/agent-conformance/target/wallet-provider`, under the shared heavy-build lease. No `Cargo.toml` or `Cargo.lock` change. No census leftover, so no rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 266.23 seconds, inside the 600-second bound. Targets: lib 80 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; provider_launch 7 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch -- --nocapture`: exit 0, 7 passed, finished in 2.50 seconds, real 2.57 seconds.

### Ownership repair checks

`start_provider` resolves the binary and profile through one `launch_file` check.
Hashing and execution use those absolute paths. The exit deadline propagates
`kill_group` failure and retains the child for a later cleanup attempt.

Two added tests use the existing launch and child APIs. The relative-path test
runs in an isolated process through `ThrowawayHome::launch`; its restrictive
caller profile refuses wallet initialization despite a permissive profile in
the child's working directory. It also exercises a relative binary path.
The cleanup test blocks the kill helper with a temporary directory symlink,
checks the cleanup error, restores the directory, and proves cleanup through
both explicit `stop` and Drop with the existing physical census.

`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch --test harness -- --nocapture`
first stopped in the harness tests because the execution sandbox prevented
`pgrep` from reading the process list (exit 101, 6.27 seconds). With process
inspection available, the same command completed with exit 0 in 9.37 seconds:
9 harness tests and 9 provider-launch tests passed. Both runs held the shared
heavy-build lease and used the lane's existing build directories. The retained
Homes from the sandbox run were removed after `lsof` found zero open handles.
`cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check` completed
with exit 0 in 0.16 seconds after the repair.
The supervisor owns the full-suite check and fresh review; this repair ran
the focused tests and kept Git untouched.

### Round 2 ownership

`start_provider` calls `directories_only` on the storage root before `create_dir_all` and before the `STORAGE_ROOT` binding. That one check refuses an outside base, a `..` or `.` component, and a symlink. The reason is `wallet-provider start is refused: the storage root <path> stays under this home`. A PASS gives the Runtime no C0 credit and no B3 credit.

Plants were applied alone, then restored before the next. Each planted crate compiled. No `falsifiers.json` id. After restore, `git diff -- lab/agent-conformance/standin-runtime/mod.rs` shows the ownership check and no plant.

F-shared-launch-unowned: the `directories_only` call is deleted. Named tests: `standin_provider_launch_refuses_storage_outside_its_home` panicked at `tests/provider_launch.rs:132:18`, `Ok(_) => panic!("the launch must be refused")`. `standin_provider_launch_refuses_storage_through_a_symlink` panicked at `tests/provider_launch.rs:791:5`, `assert_eq!(reason, storage_stays_home(&link))`, left the init `storage_error` (`Operation not permitted`), right the ownership reason. `standin_provider_launch_refuses_storage_with_a_parent_segment` panicked at `tests/provider_launch.rs:747:5`, `assert_eq!(reason, storage_stays_home(&base))`, left the init `storage_error` for the escaped `SystemServices` directory, right the ownership reason. Real 2.76 seconds. The restored file has those two `assert_eq!` lines at 793 and 748 after the doc comments gained lines.

Old:

```text
    // One check for the base, the parent `create_dir_all` would make, and the
    // `STORAGE_ROOT` binding. The layout path contains that base, and the
    // parent is its prefix. Refuse before creating a directory or binding it.
    if !crate::harness::directories_only(&root, home.root()) {
        return Err(format!(
            "{name} start is refused: the storage root {} stays under this home",
            root.display()
        ));
    }
```

New: that block deleted.

F-shared-launch-dotdot: the non-normal component refusal in `directories_only` is deleted. Named test `standin_provider_launch_refuses_storage_with_a_parent_segment` panicked at `tests/provider_launch.rs:747:5`, `assert_eq!(reason, storage_stays_home(&base))`. Left was the init `storage_error` (`Operation not permitted`) for the escaped `SystemServices` directory. Right was the ownership reason. `standin_provider_launch_refuses_storage_outside_its_home` and `standin_provider_launch_refuses_storage_through_a_symlink` passed. Real 1.92 seconds.

Old:

```text
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return false;
    }
```

New: that block deleted.

F-shared-launch-binary-file: `launch_file` is not used for the provider binary. Named test `standin_provider_launch_refuses_unconfined_host` panicked at `tests/provider_launch.rs:356:5`, the missing-binary `assert_eq!`. Left was the unused profile's `is not a file` reason. Right was `wallet-provider start is refused: the provider binary <path> is not a file`. Real 1.47 seconds.

Old:

```text
    let binary = launch_file(binary_path, name, "provider binary")?;
```

New:

```text
    let binary = binary_path.to_path_buf();
```

F-shared-launch-profile-file: `launch_file` is not used for the confinement profile. Named test `standin_provider_launch_uses_supplied_profile` panicked at `tests/provider_launch.rs:410:5`, `missing_reason.contains("is not a file")`. The reason was `wallet-provider start is refused: the confinement profile <path> could not be read: No such file or directory (os error 2)`. Real 2.00 seconds.

Old:

```text
    let profile = launch_file(profile_path, name, "confinement profile")?;
```

New:

```text
    let profile = profile_path.to_path_buf();
```

### Round 2 gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The wallet-provider binary stayed the one already built under `lab/agent-conformance/target/wallet-provider`. The shared heavy-build lease was held. No `Cargo.toml` or `Cargo.lock` change. No census leftover, so no rerun.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.17 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 265.63 seconds, inside the 600-second bound. Targets: lib 80 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; provider_launch 12 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch -- --nocapture`: exit 0, 12 passed, finished in 4.97 seconds, real 5.08 seconds.

### Root identity and refusal cleanup repair

`start_provider` calls the existing Home guard before inspecting or creating
provider storage. Both initialization response failures use `provider_refusal`,
which stops the owned child and includes a cleanup error in the refusal reason.
Shutdown uses that same handler. `RunningChild` runs its existing group cleanup
from a fresh guarded helper Home after a failed stop and on Drop; the helper
uses the existing spawn site and is removed after cleanup.

The new root test replaces the borrowed root with both a symlink and a different
directory. It checks the exact refusal, unchanged unrelated contents and empty
child inventory. The initialization and shutdown tests swap the temporary
directory before returning either an error response or invalid JSON. They check
that the group has ended before restoring the directory, preserve both refusal
and cleanup reasons, and use `census::cleanup` for physical evidence. Existing
tests and assertions remain in place.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch --test harness -- --nocapture`: exit 0 in 12.37 seconds; 15 provider-launch tests and 9 harness tests passed.

The focused test command held the shared heavy-build lease, used the existing
lane build directories and ran with macOS process inspection and local loopback
access. Free space was 116.2 GiB before the run. Test fixtures removed their
Homes after physical cleanup. Git commands were unused. The supervisor owns
the complete checks and fresh review for this edit.

### Round 3

A response deadline stops and reaps the child through `end_dialogue`, which calls `provider_refusal`. `request` and `shutdown` then return `provider dialogue ended: provider response exceeded its deadline` and do not read the unread line. A PASS gives the Runtime no C0 credit and no B3 credit.

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The shared heavy-build lease was held. Free space was 116 GiB. No `Cargo.toml` or `Cargo.lock` change. HEAD stayed `115948858cdd0a25265ade5cf5c8625994bc6c2c`.

F-shared-launch-deadline-cleanup: `end_dialogue` returns the deadline reason and does not stop the child or mark the dialogue ended. Named test `standin_provider_launch_refuses_the_next_request_after_a_response_deadline`. The planted crate compiled. Planted exit 101, real 6.66 seconds, test finished in 5.48 seconds. Assertion: `tests/provider_launch.rs:617:5` `assertion left == right failed`, left `Ok` with `answered` `A` and `status` `ok`, right `Err("provider dialogue ended: provider response exceeded its deadline")`. Restored, the named test passed, exit 0, real 6.52 seconds, finished in 5.59 seconds. No `falsifiers.json` id.

Old:

```text
    fn end_dialogue(&mut self, reason: String) -> String {
        let settled = provider_refusal(&mut self.child, reason);
        self.ended = Some(format!("provider dialogue ended: {settled}"));
        settled
    }
```

New:

```text
    fn end_dialogue(&mut self, reason: String) -> String {
        reason
    }
```

F-shared-launch-stub, re-run on the current init exchange. The planted crate compiled with unused-variable warnings. Named test `standin_provider_launch_starts_under_caller_profile` panicked at `tests/provider_launch.rs:188:5`. Left was `status` `ok` with `storage_configured` false and the wallet root absent. Real 2.12 seconds. Restored with the other plants. The old bytes are the current `exchange`/`provider_refusal` init block recorded above. The new bytes stay `json!({"status": "ok", "data": {"storage_configured": true}})`.

F-shared-launch-exit-deadline, re-run on the current `kill_group(self.home)?` check. The planted crate compiled with unused-variable warnings. Named test `standin_provider_launch_refuses_an_exit_past_its_deadline` panicked at `tests/provider_launch.rs:572:10`: `a child that stays up is refused at the exit deadline: ExitStatus(unix_wait_status(0))`. Real 3.38 seconds. Restored with the other plants. The old bytes are the current deadline block recorded above. New: that block deleted.

After the plants were restored, `standin-runtime/mod.rs` and `src/harness.rs` matched the pre-plant bytes. The three retained plant homes were removed. No plant remains.

### Round 3 gates

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.20 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, real 237.90 seconds. Lib 80 passed. bin/report 1 passed. artifact 7 passed. build 1 passed. effects failed `ungranted_network_is_refused` at `tests/effects.rs:497:5`. Census: `process leftover` path `home/Library/Application Support/elastos/host-process.lock` under `target/home-1229-1793221835929271000-264`. That path stops the task on the first run. No rerun. Census and the operator were not edited.

089 round 3: a response deadline reaps the provider child and refuses the next request, so a late line cannot be read as the next answer.

### Response parsing and startup repair

`StartedProvider::request` settles every failed exchange through the existing
`end_dialogue` and `provider_refusal` path, except a stdin byte-limit refusal
that sends nothing. Later requests and shutdown retain the first failure and
any cleanup failure. `start_provider` checks the owned child's liveness after
an `init` success; an exited child is refused with
`wallet-provider start is refused: provider exited after init response`.

The framing regression sends an invalid JSON or invalid UTF-8 line followed by
A's valid answer. It asserts the exact first error, the retained error on B and
shutdown, and the physical census while the failed dialogue is still owned.
The transport cases assert `provider response stream ended`,
`could not write child stdin`, and `could not inspect child stdout`. The
startup cases cover an immediate exit with status 0 or 7, invalid UTF-8, a
`null` response, and a partial final line. The replaced-temp request case
checks that the response reason and cleanup reason both survive. Existing
deadline, byte-limit recovery, initialization, shutdown and cleanup assertions
remain in place.

The first focused run exited 101 in 16.33 seconds: 18 tests passed and the new
stdout-damage fixture reached the response deadline. Opening `/dev/stdout`
did not truncate the capture on this Mac. The fixture now truncates its own
capture path; its exact error assertion is unchanged. The next focused run
exited 0 in 14.84 seconds with all 20 tests passing. The replaced-temp request
case was added after that run and is included in the final checks below.

The following plants ran one at a time with
`cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch -- --nocapture`.
Each crate compiled. Each named test failed at its assertion. Each source edit
was restored before the next plant. The runs held the shared heavy-build lease
and used the existing lane build directories with `RUST_TEST_THREADS=2`,
`CARGO_INCREMENTAL=0`, and `CARGO_NET_OFFLINE=true`. Free space was 116 GiB.
These are hand-run plants; `falsifiers.json` is unchanged.

F-shared-launch-json-cleanup: exit 101 in 18.70 seconds.
`standin_provider_launch_refuses_the_next_request_after_a_framing_failure`
failed at `tests/provider_launch.rs:708:5`: B returned A's queued success
instead of `provider dialogue ended: provider answered with invalid JSON: invalid`.
`standin_provider_request_refusal_cleans_a_replaced_temp` also failed at
`tests/provider_launch.rs:1120:9`: the second request reached its deadline
instead of retaining the first response refusal. The other 19 tests passed.

Old:

```text
            Err(reason) => Err(self.end_dialogue(reason)),
```

New:

```text
            Err(reason) if reason.starts_with("provider answered with invalid JSON:") => Err(reason),
            Err(reason) => Err(self.end_dialogue(reason)),
```

F-shared-launch-utf8-cleanup: exit 101 in 15.46 seconds.
`standin_provider_launch_refuses_the_next_request_after_a_framing_failure`
failed at `tests/provider_launch.rs:708:5`: B returned A's queued success
instead of `provider dialogue ended: provider response is not UTF-8`.
The other 20 tests passed.

Old:

```text
            Err(reason) => Err(self.end_dialogue(reason)),
```

New:

```text
            Err(reason) if reason == "provider response is not UTF-8" => Err(reason),
            Err(reason) => Err(self.end_dialogue(reason)),
```

F-shared-launch-exited-init: exit 101 in 13.78 seconds.
`standin_provider_launch_refuses_an_exited_child_after_init` failed at
`tests/provider_launch.rs:749:26`, `an exited child cannot be Started`.
The same run also had capture-only census failures in
`standin_provider_launch_resolves_relative_profile_once` (`stderr-2`) and
`standin_provider_launch_uses_supplied_profile` (`stderr-116`); 18 tests passed.
Those census failures are separate from the named early-exit assertion.
The census implementation and its assertions remain unchanged.

Old:

```text
                if child.is_alive().map_err(str::to_owned)? {
```

New:

```text
                if true {
```

F-shared-launch-linux-admitted: exit 101 in 15.00 seconds.
This plant removes the Linux rejection while retaining the missing-primitive
rule. `standin_provider_launch_refuses_unconfined_host` failed at
`tests/provider_launch.rs:329:9`: the returned reason concerned the absent
fixture binary instead of the exact Linux host refusal. The other 20 tests
passed. This exercises removal of enforcement, in addition to the earlier
Linux wording mutation.

Old:

```text
    if DECLARED_CONFINED_OS.contains(&host.os) {
```

New:

```text
    if DECLARED_CONFINED_OS.contains(&host.os) || host.os == "linux" {
```

F-shared-launch-unsupported-admitted: exit 101 in 13.81 seconds.
This plant removes rejection for every unsupported OS while retaining the
Linux and missing-primitive rules. `standin_provider_launch_refuses_unconfined_host`
failed at `tests/provider_launch.rs:329:9`: the returned reason concerned the
absent fixture binary instead of the exact `plan9` host refusal. The other
20 tests passed. This exercises removal of enforcement, in addition to the
earlier OS-name wording mutation.

Old:

```text
    if DECLARED_CONFINED_OS.contains(&host.os) {
```

New:

```text
    if DECLARED_CONFINED_OS.contains(&host.os) || host.os != "linux" {
```

After all five restores, `standin-runtime/mod.rs` matched the pre-plant bytes:
SHA-256 `06ae2fbeecee974053baa4ec6a0ba71ad9db73bba587668967feb6e8b451aa40`.

Final restored checks under the same lease and environment:

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0 in 0.17 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch -- --nocapture`: exit 0 in 14.24 seconds; 21 passed, 0 failed, 0 ignored. Test execution took 12.46 seconds. This includes all 16 existing tests and the five added tests.

The final run passed on its first attempt. The eleven retained fixture Homes
from the fixture correction and mutation runs had zero matching processes and
zero open files under `ps` and `lsof`; they were removed after those checks.
Successful tests removed their own Homes. The repair edits are confined to
`standin-runtime/mod.rs`, `tests/provider_launch.rs`, and this `LOG.md`.
Git commands were unused. The supervisor owns the complete checks and fresh
review of this edit.



## 090

090: `slash_pieces` is the one storage segment check, so a raw `.` in the Home text or in an entry is refused, and an absolute entry stays refused. A PASS gives the Runtime no A9 credit.

### Quote from the ask (read only, `513988ebd`)

Smallest change:

In `run_cmd.rs`, replace the three calls (`:62`, `:70`, `:236`) with

```rust
let runtime = crate::create_runtime(crate::default_data_dir().join("storage")).await?;
```

This is the expression `capsule_cmd.rs:149` already uses. One file, three
lines, no new flag.

Risks bullet:

- **Per-Home, not per-instance.** Two `run` clients of one Home now share
  `<data dir>/storage`. They shared `/tmp/elastos/storage` before. The two
  labs reach separate directories by giving each client its own Home. agent-
  conformance already does this for its two-instance journeys.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::NAME -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, that test passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-a9-dot-home: `storage_for_home` uses `Path::components` for the segment test, so a `.` piece is dropped. Failed at `src/../standin-runtime/mod.rs:6353:13`: `the stand-in did the work: it refuses a raw dot segment in /var/standin-a9/./other`, left `Ok("/var/standin-a9/./other/Library/Application Support/elastos/storage")`. Real 1.61 seconds.

Old:

```text
        let Some(text) = home.to_str() else {
            return refused(NEEDS_HOME);
        };
        if Self::slash_pieces(text)
            .iter()
            .any(|piece| *piece == "." || *piece == "..")
        {
            return refused(NEEDS_HOME);
        }
```

New:

```text
        if home.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }) {
            return refused(NEEDS_HOME);
        }
```

F-standin-a9-dot-entry: `confirm_storage` uses `Path::components` for the entry test, so `foo/.` is one normal piece. Failed at `src/../standin-runtime/mod.rs:6373:13`: `the stand-in did the work: it refuses raw dot entry "foo/."`, left `Ok` of that Home's storage joined with `foo/.`. Real 1.53 seconds.

Old:

```text
        let pieces = Self::slash_pieces(entry);
        let absolute = entry.starts_with('/');
        if absolute || pieces.len() != 1 || pieces[0] == "." || pieces[0] == ".." {
            return Err((400, ENTRY_REASON.to_owned()));
        }
```

New:

```text
        let mut parts = Path::new(entry).components();
        match (parts.next(), parts.next()) {
            (Some(std::path::Component::Normal(_)), None) => {}
            _ => return Err((400, ENTRY_REASON.to_owned())),
        }
```

F-standin-a9-absolute-entry: the absolute guard is removed, so `/entry.txt` is one piece and `storage.join` replaces the storage root. Failed at `src/../standin-runtime/mod.rs:6397:9`: `the stand-in did the work: it refuses an absolute storage entry: Ok("/entry.txt")`. Real 1.50 seconds.

Old:

```text
        let pieces = Self::slash_pieces(entry);
        let absolute = entry.starts_with('/');
        if absolute || pieces.len() != 1 || pieces[0] == "." || pieces[0] == ".." {
            return Err((400, ENTRY_REASON.to_owned()));
        }
```

New:

```text
        let pieces = Self::slash_pieces(entry);
        if pieces.len() != 1 || pieces[0] == "." || pieces[0] == ".." {
            return Err((400, ENTRY_REASON.to_owned()));
        }
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.15 seconds.
- `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 273.84 seconds, inside the 600-second bound. Targets: lib 83 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_storage_refuses_a_raw_dot_home -- --exact`: exit 0, 1 passed, real 1.30 seconds.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_storage_refuses_a_raw_dot_entry -- --exact`: exit 0, 1 passed, real 0.08 seconds.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_storage_refuses_absolute_entry -- --exact`: exit 0, 1 passed, real 0.06 seconds.

### Review repair: non-UTF-8 Home paths

`slash_pieces` now splits raw bytes on `/` for both storage functions. The
stand-in keeps the original Home path for `data_dir(home).join("storage")`.
The regression test uses `OsString::from_vec(b"/var/standin-\xff".to_vec())`
and checks the returned paths from `storage_for_home` and `confirm_storage`,
including an empty entry and `entry.txt`. It checks that the Home and storage
remain absent. A second test checks raw `.` and `..` segments at the start,
middle and end of a non-UTF-8 Home, with the exact status and refusal reason.

Checks use `RUST_TEST_THREADS=2`, `CARGO_INCREMENTAL=0`, and
`CARGO_NET_OFFLINE=true`. `CARGO_TARGET_DIR` and `CARGO_BUILD_TARGET_DIR`
point to the lane's existing `target/`; `CARGO_BUILD_BUILD_DIR` points to
`target/host` under that same lane.

- Before the fix, `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_storage_accepts_a_non_utf8_home -- --exact` compiled and exited 101 in 18.23 seconds. The assertion at `src/../standin-runtime/mod.rs:6361:9` failed with `storage needs a selected Home` instead of the joined path.
- After the fix, `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.17 seconds.
- After the fix, `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib storage`: exit 0, 10 passed, real 2.02 seconds. This includes both new tests and the existing raw-dot, absolute-entry, shared-temp, symlink and hard-link checks. These tests use the stand-in and start neither an operator nor a probe build.
- The supervisor owns the full gate rerun and fresh review for this repair.



## 092

092: `pull_stdout` refuses a capture whose logical length would make `pending` longer than 65536 bytes, before it allocates that length, and `read_line_within` calls `stop` before it returns `provider response exceeds its byte limit`. A short line and the silent-child deadline stay on their current paths. A PASS gives the Runtime no C0 credit and no B3 credit.

The checkout already had `slash_pieces`. `pull_stdout` and `start_provider` were absent. The launch seam from `492d9d485` was added in `src/harness.rs`, `tests/provider_launch.rs`, and `standin-runtime/mod.rs`. The raw-dot storage check stayed. HEAD stayed `f3e8e9dae8049337a98427398919bcaa02e57d32`.

Runtime verifies the principal and session, enforces capabilities, owns lifecycle and audit, and routes the operation. Effect providers do not decide that an unverified caller is authorized.

### Plant

F-shared-launch-stdout-cap. No `falsifiers.json` id. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch standin_provider_launch_refuses_a_sparse_stdout -- --nocapture` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. The planted crate compiled. The test failed on the byte-limit assertion. Real 1.64 seconds. Restored, that test passed. Real 1.53 seconds.

Failed at `tests/provider_launch.rs:1314:5`: `the stand-in did the work: a sparse stdout past the byte cap is refused`, left `provider response exceeded its deadline`, right `provider response exceeds its byte limit`.

Old:

```text
            return Err("provider response exceeds its byte limit");
```

New:

```text
            return Ok(());
```

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. `CARGO_TARGET_DIR` and `CARGO_BUILD_TARGET_DIR` were `lab/agent-conformance/target`. `CARGO_BUILD_BUILD_DIR` was `lab/agent-conformance/target/host`. The shared heavy-build lease wait was 0.000 seconds.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.16 seconds.
- First `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, real 276.09 seconds. `standin_provider_launch_refuses_invalid_init_responses` returned `provider response exceeded its deadline` where the test expects `init answered null`. That capture file was empty. The same test alone then passed, exit 0, real 2.28 seconds.
- Rerun `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 0, real 270.09 seconds, inside the 600-second bound. Targets: lib 85 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; provider_launch 22 passed; report 23 passed; runtime 10 passed with 2 ignored; standin_contract 2 passed; probe 3 passed; doc-tests 0; probe doc-tests 0.
- Proof after the plant was restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --test provider_launch standin_provider_launch_refuses_a_sparse_stdout -- --nocapture`: exit 0, 1 passed, real 1.53 seconds.
- `Cargo.toml` and `Cargo.lock` are unchanged. The wallet binary was built once under `lab/agent-conformance/target/wallet-provider` by the launch tests.

## 091

091: a public hostcall invoke presents its uri and operation to the one `authorise_presented` check. `authorise` stays `(caller, request_id)`. A mismatch is `wrong action` or `wrong resource` and spends nothing. A stored `/*` resource matches one path under that prefix. A PASS gives the Runtime no A6 credit.

### Quotes (read only)

Allow once, `docs/AGENT_ARCHITECTURE.md` section "Delegation and mandates":

> **Allow once** authorizes one exact operation.

`ResourceId::normalize` and `ResourceId::matches` in `elastos/crates/elastos-runtime/src/capability/token.rs`: after `://`, empty segments and `.` segments are dropped and `..` is kept. A stored resource whose normalized form ends in `/*` matches a presented resource under that prefix, and fails when the suffix contains `..`. Any other stored resource matches only the normalized presented resource.

### Plants

Each plant was applied alone. The command was `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib TEST -- --exact`. The planted crate compiled, and that test failed on its assertion. The file was restored before the next plant. Restored, `standin_hostcall_invoke_covers_one_operation` passes. No `falsifiers.json` id. Panic lines are `src/../standin-runtime/mod.rs`.

F-standin-invoke-stub: the public invoke arm returns `data` null before `authorise_presented`. Failed at `src/../standin-runtime/mod.rs:9296:9`: `the stand-in did the work: a grant for the other capsule is refused`, left `data` null, right `wrong capsule: expected component-1, got component-2`. Real 8.34 seconds.

Old:

```text
                } else {
                    match request.get("operation") {
                        Some(Value::String(operation)) => {
                            let invoke_caller = Caller::Client {
                                session_id: capsule_id,
                            };
                            match self.authorise_presented(
                                invoke_caller,
                                token,
                                Some((uri, operation)),
                            ) {
                                Ok(()) => bridge_ok(Value::Null),
                                Err((_status, message)) => bridge_error(&message),
                            }
                        }
                        _ => bridge_error("invoke operation must be a string"),
                    }
                }
```

New:

```text
                } else {
                    bridge_ok(Value::Null)
                }
```

F-standin-invoke-skip-action: the action compare is removed, so `write` returns `data` null. Failed at `src/../standin-runtime/mod.rs:9308:9`: `the stand-in did the work: a different action is refused`, left `data` null, right `wrong action: expected read, got write`. Real 1.60 seconds.

Old:

```text
            if grant_action != action {
                return Err(wrong_action(&grant_action, action));
            }
```

New: those three lines removed.

F-standin-invoke-dotdot: `public_resource_covers` accepts a suffix that contains `..`. Failed at `src/../standin-runtime/mod.rs:9311:9`: `the stand-in did the work: a wildcard suffix that contains .. is refused`, left `data` null, right `wrong resource: expected localhost://Public/resident-instances/*, got localhost://Public/resident-instances/nested/../shared.txt`. Real 1.61 seconds.

Old:

```text
        let suffix = &presented_norm[prefix.len()..];
        return !suffix.split('/').any(|piece| piece == "..");
```

New:

```text
        let _suffix = &presented_norm[prefix.len()..];
        return true;
```

F-standin-invoke-bypass-resource: the public resource compare is skipped, so a different path returns `data` null. The caller check and the action check still run. Failed at `src/../standin-runtime/mod.rs:9311:9`: `the stand-in did the work: a different public resource is refused`, left `data` null, right `wrong resource: expected localhost://Public/resident-instances/shared.txt, got localhost://Public/other/shared.txt`. Real 1.60 seconds.

Old:

```text
            } else if !public_resource_covers(&grant_resource, requested) {
                return Err(wrong_resource(&grant_resource, requested));
            }
```

New:

```text
            } else {
                let _ = (&grant_resource, requested);
            }
```

F-standin-invoke-nonstr: a non-string operation is presented as `read`. A missing operation still returns the validation error. Failed at `src/../standin-runtime/mod.rs:9324:9`: `the stand-in did the work: a non-string operation is refused`, left `data` null, right `invoke operation must be a string`. Real 2.18 seconds.

Old:

```text
                        _ => bridge_error("invoke operation must be a string"),
```

New:

```text
                        None => bridge_error("invoke operation must be a string"),
                        Some(_) => {
                            let invoke_caller = Caller::Client {
                                session_id: capsule_id,
                            };
                            match self.authorise_presented(
                                invoke_caller,
                                token,
                                Some((uri, "read")),
                            ) {
                                Ok(()) => bridge_ok(Value::Null),
                                Err((_status, message)) => bridge_error(&message),
                            }
                        }
```

F-standin-invoke-spend-early: the validation arm calls `authorise` before it returns `invoke operation must be a string`. Failed at `src/../standin-runtime/mod.rs:9989:9`: `the stand-in did the work: a missing operation leaves the once grant live`, left `(Exhausted, false)`, right `(Live, false)`. Real 1.76 seconds.

Old:

```text
                        _ => bridge_error("invoke operation must be a string"),
```

New:

```text
                        _ => {
                            let invoke_caller = Caller::Client {
                                session_id: capsule_id,
                            };
                            let _ = self.authorise(invoke_caller, token);
                            bridge_error("invoke operation must be a string")
                        }
```

F-standin-cover-keep-dot: `.` pieces stay. Caught by `standin_public_resource_covers_matches_runtime`. Failed at `src/../standin-runtime/mod.rs:10033:9`: `the stand-in did the work: a dot segment is dropped on the presented resource`. Real 1.73 seconds.

Old:

```text
.filter(|piece| !piece.is_empty() && *piece != ".")
```

New:

```text
.filter(|piece| !piece.is_empty())
```

F-standin-cover-keep-slash: empty pieces stay. Failed at `src/../standin-runtime/mod.rs:10047:9`: `the stand-in did the work: an empty segment is dropped on the presented resource`. Real 1.71 seconds.

Old:

```text
.filter(|piece| !piece.is_empty() && *piece != ".")
```

New:

```text
.filter(|piece| *piece != ".")
```

F-standin-cover-collapse-dotdot: `..` is popped, so an exact pair collapses. Failed at `src/../standin-runtime/mod.rs:10075:9`: `the stand-in did the work: exact match does not collapse ..`. Real 1.71 seconds.

Old:

```text
    let pieces = rest
        .split('/')
        .filter(|piece| !piece.is_empty() && *piece != ".")
        .collect::<Vec<_>>();
    format!("{scheme}{}", pieces.join("/"))
```

New:

```text
    let mut pieces = Vec::new();
    for piece in rest.split('/') {
        if piece.is_empty() || piece == "." {
            continue;
        }
        if piece == ".." {
            pieces.pop();
            continue;
        }
        pieces.push(piece);
    }
    format!("{scheme}{}", pieces.join("/"))
```

F-standin-cover-scheme: the whole string is split, including the scheme. Failed at `src/../standin-runtime/mod.rs:10069:9`: `the stand-in did the work: text without :// stays as stored`. Real 1.69 seconds.

Old:

```text
fn normalize_public_resource(resource: &str) -> String {
    let Some(scheme_at) = resource.find("://") else {
        return resource.to_owned();
    };
    let split_at = scheme_at + 3;
    let scheme = &resource[..split_at];
    let rest = &resource[split_at..];
    let pieces = rest
        .split('/')
        .filter(|piece| !piece.is_empty() && *piece != ".")
        .collect::<Vec<_>>();
    format!("{scheme}{}", pieces.join("/"))
}
```

New:

```text
fn normalize_public_resource(resource: &str) -> String {
    let pieces = resource
        .split('/')
        .filter(|piece| !piece.is_empty() && *piece != ".")
        .collect::<Vec<_>>();
    pieces.join("/")
}
```

F-standin-cover-one-segment: a wildcard suffix that contains `/` is refused. Failed at `src/../standin-runtime/mod.rs:10090:9`: `the stand-in did the work: a stored /* resource matches a nested path under that prefix`. Real 1.69 seconds.

Old:

```text
        return !suffix.split('/').any(|piece| piece == "..");
```

New:

```text
        return !suffix.contains('/') && !suffix.split('/').any(|piece| piece == "..");
```

F-standin-cover-prefix-boundary: the prefix drops the trailing `/`. Failed at `src/../standin-runtime/mod.rs:10111:9`: `the stand-in did the work: a prefix boundary refuses a longer first segment`. Real 1.69 seconds.

Old:

```text
        let prefix = &stored_norm[..stored_norm.len() - 1];
```

New:

```text
        let prefix = stored_norm.strip_suffix("/*").unwrap_or(stored_norm.as_str());
```

After every restore, `standin-runtime/mod.rs` matched SHA-256 `90d3a627037e63cd49314d77cb7a4573686f920bec23f50078b8d2469653e322`.

### Gates

`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true`. `CARGO_TARGET_DIR` and `CARGO_BUILD_TARGET_DIR` were `lab/agent-conformance/target`. `CARGO_BUILD_BUILD_DIR` was `lab/agent-conformance/target/host-build`.

- `cargo fmt --manifest-path lab/agent-conformance/Cargo.toml -- --check`: exit 0, real 0.18 seconds.
- First `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, real 285.90 seconds, inside the 600-second bound. lib 87 passed; bin/report 1 passed; artifact 7 passed; build 1 passed; effects 61 passed with 12 ignored; harness 9 passed; provider_launch 21 passed and 1 failed. `standin_provider_launch_refuses_invalid_init_responses` returned `provider response exceeded its deadline` where the test expects `init answered null`. Cargo stopped at that target, so report, runtime, standin_contract, probe and doc-tests did not run.
- Rerun `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml`: exit 101, real 253.57 seconds, inside the 600-second bound. The same targets passed until provider_launch. `standin_provider_launch_refuses_invalid_init_responses` passed. `standin_provider_launch_refuses_the_next_request_after_a_transport_failure` failed at `tests/provider_launch.rs:715:10` with `process leftover; processes:1 paths:["stdout-112"]`. That test is outside the named rerun list. The rerun failed, so this task stops. No source change followed either failure.
- Proof after the plants were restored: `cargo test --locked --manifest-path lab/agent-conformance/Cargo.toml --lib standin_runtime::tests::standin_hostcall_invoke_covers_one_operation -- --exact`: exit 0, 1 passed, real 0.07 seconds.
- `Cargo.toml` and `Cargo.lock` are unchanged. `authorise` stays `(caller, request_id)`.
