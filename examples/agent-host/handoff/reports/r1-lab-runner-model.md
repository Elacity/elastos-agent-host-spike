# R1: the Wasm lab runs through the existing falsifier runner (model comparison)

Slice:        task 021, `lab` registered in the one crate table plus the six lab
              recovery targets, with the model list compared by entry id
Status:       runner and model list changed; model full run, self-test, load checks
              and lane checks recorded here. Real DID, wallet, lab and default
              agent-host mutation runs stay with their owners.
Base commit:  118d42d3a95838b479d992a234411babcb26ff64
Base tree:    eaeeb34fcce124eae5bad6f6be098a04e31279b9
Working tree: the two intended edits below, uncommitted at the time of these runs
Scratch:      `examples/agent-host/handoff/reports/.r1-lab-runner/` (owned and
              removed after the evidence was copied here); short socket-fixture
              `TMPDIR=/tmp/r1-lab-runner-tmp` (removed)

## Identity

| Object | Before edits | After edits |
| --- | --- | --- |
| `examples/agent-host/falsify.py` SHA-256 | `f4a9748d66293f78450aec1ea2b0afd130c9c42af06e5ddfd49d2a0b1174581c` | `54308b2c868aa6c39f44b1a88eb13c4e565148844ff0aac313f603c5a293a53c` |
| `capsules/model-provider/falsifiers.json` SHA-256 | `f763b203193d8a7b1615690de00cf61c204d856ef5f370e5f64570d6d1ec88d5` | `6040948ec4ed02594b33f5db360a5a59754caae71ed229f4a8bb0cd3b7c35ecc` |

Inputs read but not changed:

- `lab/wasm-capsule/falsifiers.json` SHA-256 `6991fd5ea67ed051e60d70e1fc3fe07658b2eb299a36015b5bccae4278a1c768`, 33 entries.
- `lab/wasm-capsule/audit/falsifiers.json` SHA-256 `ee017191cfad110044606aef18a9c8059e70fe4b078960e2746c9629657d89b4`, 49 entries.
- `lab/wasm-capsule/Cargo.toml` (workspace root package `capsule`, members `audit`, `tools`) and `lab/wasm-capsule/audit/Cargo.toml`.

## Environment

- macOS Darwin 25.5.0, arm64; Python 3.9.6; cargo 1.91.0 (ea2d97820 2025-10-10); rustc 1.91.0 (f8297e351 2025-10-28).
- `RUST_TEST_THREADS=2`, `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR=<scratch>/target`,
  `CARGO_BUILD_BUILD_DIR=<scratch>/build`.
- Every Cargo run held the shared heavy-build lease
  `fcntl.flock` on `/Users/sash/code/elastos-runtime/.git/local-ai-heavy-build.lock`.
- Free space before the runs was about 28 GiB, above `FALSIFY_MIN_FREE_BYTES` (2 GiB) plus the build need.

## Load checks for the real lab lists (before, then after)

Command, run from `examples/agent-host`:

```bash
python3 -I falsify.py --keep-backups --from <list> --list
```

Before the edit each list refused `lab` with status 2 and its unknown-command reason:

```text
../../lab/wasm-capsule/falsifiers.json: F-WC1: unknown command 'lab'
exit=2
../../lab/wasm-capsule/audit/falsifiers.json: F-CWA0a: unknown command 'lab'
exit=2
```

After the edit each loaded and displayed every base-version entry, exit 0:

```text
lab/wasm-capsule/falsifiers.json -> exit=0, 33 entries
lab/wasm-capsule/audit/falsifiers.json -> exit=0, 49 entries
```

The six edit targets of those lists, resolved from `examples/agent-host`:
`../../lab/wasm-capsule/capsule/src/lib.rs`, `../../lab/wasm-capsule/tools/build`,
`../../lab/wasm-capsule/tools/src/lab_name.rs`, `../../lab/wasm-capsule/audit/Cargo.toml`,
`../../lab/wasm-capsule/audit/INTERFACE.md`, `../../lab/wasm-capsule/audit/src/lib.rs`.

## Model list, before the edit (task base)

Command, run from the repository root under the lease:

```bash
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json
```

Result: `summary: 80 CAUGHT of 80`, exit 0, wall time 134.93 s.

Per-entry verdicts, all `CAUGHT`:

```text
PV01=CAUGHT PV02=CAUGHT PV03=CAUGHT PV04=CAUGHT PV05=CAUGHT PV06=CAUGHT PV07=CAUGHT PV08=CAUGHT
PV09=CAUGHT PV10=CAUGHT PV11=CAUGHT PV12=CAUGHT PV13=CAUGHT PV14=CAUGHT PV15=CAUGHT PV16=CAUGHT
PV17=CAUGHT PV18=CAUGHT PV19=CAUGHT PV20=CAUGHT PV21=CAUGHT PV22=CAUGHT PV23=CAUGHT PV24=CAUGHT
PV25=CAUGHT PV26=CAUGHT PV27=CAUGHT PV28=CAUGHT PV29=CAUGHT PV30=CAUGHT PV31=CAUGHT PV32=CAUGHT
PV33=CAUGHT MP01=CAUGHT MP02=CAUGHT MP03=CAUGHT MP04=CAUGHT MP05=CAUGHT MP06=CAUGHT MP07=CAUGHT
MP08=CAUGHT MP09=CAUGHT MP10=CAUGHT MP11=CAUGHT MP12=CAUGHT MP13=CAUGHT MP14=CAUGHT MP15=CAUGHT
MP16=CAUGHT PV34=CAUGHT PV35=CAUGHT PV36=CAUGHT PV37=CAUGHT PV38=CAUGHT PV39=CAUGHT PV40=CAUGHT
PV41=CAUGHT PV42=CAUGHT PV43=CAUGHT PV44=CAUGHT PV45=CAUGHT PV46=CAUGHT PV47=CAUGHT PV48=CAUGHT
PV49=CAUGHT PV50=CAUGHT PV51=CAUGHT PV52=CAUGHT PV53=CAUGHT PV54=CAUGHT PV55=CAUGHT PV56=CAUGHT
PV57=CAUGHT PV58=CAUGHT PV59=CAUGHT PV60=CAUGHT PV61=CAUGHT PV62=CAUGHT PV63=CAUGHT PV64=CAUGHT
```

## Model list, after the edit

Same command and environment. Result: `summary: 90 CAUGHT of 90`, exit 0.
The after run and the self-test together took 132.01 s of wall time.

Per-entry verdicts, all `CAUGHT`:

```text
PV01=CAUGHT PV02=CAUGHT PV03=CAUGHT PV04=CAUGHT PV05=CAUGHT PV06=CAUGHT PV07=CAUGHT PV08=CAUGHT
PV09=CAUGHT PV10=CAUGHT PV11=CAUGHT PV12=CAUGHT PV13=CAUGHT PV14=CAUGHT PV15=CAUGHT PV16=CAUGHT
PV17=CAUGHT PV18=CAUGHT PV19=CAUGHT PV20=CAUGHT PV21=CAUGHT PV22=CAUGHT PV23=CAUGHT PV24=CAUGHT
PV25=CAUGHT PV26=CAUGHT PV27=CAUGHT PV28=CAUGHT PV29=CAUGHT PV30=CAUGHT PV31=CAUGHT PV32=CAUGHT
PV33=CAUGHT MP01=CAUGHT MP02=CAUGHT MP03=CAUGHT MP04=CAUGHT MP05=CAUGHT MP06=CAUGHT MP07=CAUGHT
MP08=CAUGHT MP09=CAUGHT MP10=CAUGHT MP11=CAUGHT MP12=CAUGHT MP13=CAUGHT MP14=CAUGHT MP15=CAUGHT
MP16=CAUGHT PV34=CAUGHT PV35=CAUGHT PV36=CAUGHT PV37=CAUGHT PV38=CAUGHT PV39=CAUGHT PV40=CAUGHT
PV41=CAUGHT PV42=CAUGHT PV43=CAUGHT PV44=CAUGHT PV45=CAUGHT PV46=CAUGHT PV47=CAUGHT PV48=CAUGHT
PV49=CAUGHT PV50=CAUGHT PV51=CAUGHT PV52=CAUGHT PV53=CAUGHT PV54=CAUGHT PV55=CAUGHT PV56=CAUGHT
PV57=CAUGHT PV58=CAUGHT PV59=CAUGHT PV60=CAUGHT PV61=CAUGHT PV62=CAUGHT PV63=CAUGHT PV64=CAUGHT
PV65=CAUGHT PV66=CAUGHT PV67=CAUGHT PV68=CAUGHT PV69=CAUGHT PV70=CAUGHT PV71=CAUGHT PV72=CAUGHT
PV73=CAUGHT PV74=CAUGHT
```

### Comparison by entry id

- Existing entries: the 80 ids in the before run each keep the same verdict
  `CAUGHT`; no id was removed, retitled, or changed in expectation. There are no
  `NOT RUN`, `SURVIVED` or `compile_error` verdicts in either run.
- Added entries (explaining 80 -> 90), all `CAUGHT`:
  - `PV65` the lab is not a registered command
  - `PV66` the lab command builds the capsule-identity manifest
  - `PV67` the lab command omits its workspace selection
  - `PV68` the provider command gains the lab's workspace selection
  - `PV69` startup recovery skips the lab capsule's source
  - `PV70` startup recovery skips the lab's build script
  - `PV71` startup recovery skips the lab's name rule
  - `PV72` startup recovery skips the audit crate's manifest
  - `PV73` startup recovery skips the audit crate's interface document
  - `PV74` startup recovery skips the audit crate's source
- Targeted run of the added entries before the full run:
  `python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json PV65 PV66 PV67 PV68 PV69 PV70 PV71 PV72 PV73 PV74`
  -> `summary: 10 CAUGHT of 10`, exit 0.

### Retargeted existing anchors

The table representation change moved five anchors; each keeps its id, planted
defect, expectation and named tests:

| Id | Anchor before | Anchor after |
| --- | --- | --- |
| `PV11` | `spec()` cargo line naming `PROVIDER_CRATES[command]` | same line naming `crate_manifest` |
| `PV14` | same line | same line |
| `PV17` | same line | same line |
| `PV43` | `"did": REPO / ...` table row | `"did": (REPO / ..., ())` row |
| `PV50` | `"capsule-identity": REPO / ...` row | `"capsule-identity": (..., ())` row |

`PV09` keeps its `COMMANDS` anchor unchanged because `COMMANDS` still derives
from the table.

## Self-test

```bash
python3 -I examples/agent-host/falsify.py --self-test
```

Result: `self-test: OK`, exit 0. Both startup modes of
`a killed provider edit is recovered` report
`restored=True, foreign kept=True`; the two new neighbouring lab files
(`lab/wasm-capsule/README.md`, `lab/wasm-capsule/tools/Cargo.toml`) stay foreign,
and the six lab recovery targets are planted as synthetic originals in the
isolated tree.

## Lane checks

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path capsules/model-provider/Cargo.toml -- --check` | exit 0 |
| `cargo test --locked --manifest-path capsules/model-provider/Cargo.toml` (`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`) | first run exit 101: `hosted_runtime_refusal_keeps_owner_access_distinct_from_provider_403` panicked with `path must be shorter than SUN_LEN`, because the scratch `TMPDIR` path plus the fixture name exceeded `sun_path`; rerun with `TMPDIR=/tmp/r1-lab-runner-tmp` exit 0: 299 lib tests passed, 2 ignored; `tests/confine/main.rs` 17 passed; `tests/process.rs` 8 passed. No provider behavior changed. |
| `python3 -I examples/agent-host/falsify.py --self-test` | `self-test: OK`, exit 0 |
| `python3 -I examples/agent-host/falsify.py --list capsules/model-provider/falsifiers.json` | exit 0 (loads and displays the default agent-host list; the path token is an id filter, as the lane command is written) |
| `git diff --check` | clean |

## Recovery targets added

`PROVIDER_TARGETS` gains these six paths after the capsule-identity targets and
before `local_llama.rs`, so the existing first and last targets keep their
positions:

```text
lab/wasm-capsule/capsule/src/lib.rs
lab/wasm-capsule/tools/build
lab/wasm-capsule/tools/src/lab_name.rs
lab/wasm-capsule/audit/Cargo.toml
lab/wasm-capsule/audit/INTERFACE.md
lab/wasm-capsule/audit/src/lib.rs
```

## Skipped checks and owner-run proof

- Real DID, wallet, lab and default agent-host mutation runs are owned by the
  confine owner, the two Wasm lab owners and the supervisor. This builder did
  not run them and did not build another lane's crate.
- The supervisor's full default agent-host gate result is not supplied; it is
  recorded when the supervisor supplies it.
- Installed-artifact and Browser proof do not apply: the change edits the test
  runner and its data only.

Remaining proof for task 022: the lab owners run
`python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json`
and the audit list through the registered `lab` command, and the supervisor's
default agent-host gate passes. This task claims no grade point; row 10 stays
5 of 5 and the total stays 46 of 70.
