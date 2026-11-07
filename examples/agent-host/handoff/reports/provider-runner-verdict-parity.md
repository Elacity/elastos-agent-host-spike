# Provider runner verdict parity and the R1 wind-down gate

```text
Slice:        task 022 (proof only: no runner, list, test, provider or grade change)
Lane:         provider; the builder runs the model list, and DID and wallet stay
              with their owner
Status:       BLOCKED: both model comparisons pass with full executions, and the
              DID, wallet, lab and supervisor default-list receipts are missing
Base:         spike/spike/agent-host
Worktree:     9f8c7d19755b9091032f65c1ff44a46bae3ac40e, tree
              fa82c663d3e9f6ce750c207bcbe8370d6c57b1f8
Machine:      macOS 26.5.2, Darwin 25.5.0 arm64 (Apple silicon); Python 3.9.6;
              cargo 1.91.0 (ea2d97820 2025-10-10); rustc 1.91.0 (f8297e351 2025-10-28);
              /usr/bin/sandbox-exec present; about 23 GiB free, above
              FALSIFY_MIN_FREE_BYTES (2 GiB)
Changed:      this report, plus one line in examples/agent-host/handoff/LOG.md
Grade:        unchanged: 46 of 70 (reports/grade-rescore-3.md); row 10 stays 5,
              row 12 stays 4, row 14 stays 1
Owner:        provider builder wrote this record; Flint routes the missing runs
```

The task asks for one thing: show that the 020 and 021 runner changes kept every
existing list verdict, and then record whether the R1 wind-down gate is closed. A
list verdict counts only when the one runner executed every entry of the list on
the tested source. This report separates three kinds of check, because a load or
display check and a selected-id run are not list executions:

| Kind | What it does | Where it is used here |
| --- | --- | --- |
| source inspection | reads code, lists or commits | identity and anchor tables |
| command construction and load | `--list` prints the loaded entries; a selected id runs one entry | lane checks, lab load checks; never a verdict |
| full list execution | the runner applies and restores every entry of one list | the model list only |

## Overall result

| Acceptance item | Result | Evidence |
| --- | --- | --- |
| 1. Two comparisons with identities | PASS for the model list; BLOCKED for DID and wallet | identities and receipts below |
| 2. Full executions, every entry, all counts | PASS for the model list; BLOCKED for DID and wallet | three model executions with 76, 80 and 90 entries |
| 3. Clean suites, Mac sandbox, restoration | PASS on this source and on both candidate sources; BLOCKED for the base's own test-source suite | suite table below |
| 4. R1 lab runs (root and audit) | BLOCKED: no execution receipt, and the root list changed after R1 | lab section below |
| 5. Explicit overall result | BLOCKED | missing receipts and their next owners |
| 6. One LOG line | done | LOG entry for 022 |

The model half of the proof is complete: 76 entries at 020's base, 80 at 020's
tested candidate, and 90 at 021's tested candidate all print `CAUGHT` for every
entry, and each pre-existing entry keeps its id, rule, named tests and verdict.
The gate stays open because the confine owner's DID and wallet runs, the two lab
owners' runs and the supervisor's default-list run have no receipt that this
repository can check. Flint owns the routing of those runs, and STOP waits for
R1 and this proof to merge.

## Identity of every tested side

All hashes are SHA-256. "Model test source" names the git tree of
`capsules/model-provider/src` and `capsules/model-provider/tests`; the crate
manifest and lockfile are unchanged at every side (`Cargo.toml` `f16f1328…`,
`Cargo.lock` `5e2a06a1…`), so the build inputs stay constant.

| Side | Source commit | Source tree | Runner | Model list | Model test source (src / tests) | Owner | Run result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 020 base | `552bef4d5` (PR #151 merge, the planning commit) | `1ced4375…` | `650e25ae…` | `b26dc734…`, 76 entries | `c49199ce…` / `2f7797e3…` | provider builder | replay: 76 CAUGHT, exit 0 |
| 020 candidate | `7b2e8ee31` (branch head, tree `a826a2e1…`); merged as `118d42d3a` | `a826a2e1…` | `f4a9748d…` | `f763b203…`, 80 entries | `c49199ce…` / `14eebb4a…` | provider builder (020 and 021 receipts) | 80 CAUGHT, exit 0 |
| 021 base | `118d42d3a` (PR #155 merge) | `eaeeb34f…` | `f4a9748d…` | `f763b203…`, 80 entries | `c49199ce…` / `14eebb4a…` | provider builder (021 receipt) | 80 CAUGHT, exit 0 |
| 021 candidate | tested tree = `118d42d3a` plus runner `54308b2c…` and list `6040948e…`; committed as `492677d78`, merged as `9f8c7d197` | `9f8c7d197` = `fa82c663…` | `54308b2c…` | `6040948e…`, 90 entries | `c49199ce…` / `14eebb4a…` | provider builder (021 receipt) | 90 CAUGHT, exit 0 |

Other identities that stay constant:

- `examples/agent-host/falsifiers.json` (the default list the runner names as
  `DATA`): `d79e9bcf…`, 144 entries at every side.
- `examples/agent-host/src` tree: `03345eb0…` at every side.
- DID list: `feffe9f9…`, 21 entries; wallet list: `f2cbc08f…`, 27 entries. Both
  are identical at every side, so the runner is the only variable in their pair.
- Toolchain: one Mac and one Rust toolchain, `1.91.0`, for every run below.

The two sides of each pair do not hold every provider file constant, because the
candidate branches merged the upstream line. This table records those
integration changes instead of attributing them to the runner:

| Pair | Files that differ because of integration | Effect on the verdicts |
| --- | --- | --- |
| 020 base to candidate | `capsules/model-provider/tests/confine/main.rs` (`2f7797e3` to `14eebb4a`, cc-model-confine's merge), plus that crate's `CONFINEMENT.md` and `confine-falsifiers.json` | no model entry names a confine test; its binary runs with a filter that matches nothing, and it printed no error marker in any run |
| 021 base to candidate | only `examples/agent-host/falsify.py` and `capsules/model-provider/falsifiers.json` on the paths the model list touches | the list and the runner are the tested change |

## Pair 1: 020's base against its tested candidate (model list)

Commands, run from the repository root under the shared heavy-build lease
(`fcntl.flock` on `/Users/sash/code/elastos-runtime/.git/local-ai-heavy-build.lock`)
with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`, a workspace-local
`CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`, and a short `TMPDIR`:

```bash
# base side (replay of the base runner and base list, labelled below)
python3 -I examples/agent-host/falsify.py \
  --from capsules/model-provider/.022-replay/base-falsifiers.json
# candidate side (the 021 base receipt, whose runner and list bytes are the 020 candidate's)
python3 -I examples/agent-host/falsify.py \
  --from capsules/model-provider/falsifiers.json
```

### Base side

A replay is the only reachable form of the base receipt: task 019 recorded the
summary `summary: 76 CAUGHT of 76` but not the per-entry output, and its tested
harness was `db61d843…`, which is not the base's `2f7797e3…`. The replay ran the
base runner bytes and the base list bytes. It wrote them at the runner's own path,
ran under the lease, and restored the head bytes immediately afterwards; the
`--from` path is a scratch copy because the committed list now holds 90 entries.
The replay is labelled as a replay, and it is not a receipt of the base commit.

- Runner `650e25ae…` (the base bytes), list `b26dc734…` (the base bytes, 76 entries).
- Source: checkout `9f8c7d197`; every file the list edits is byte-identical to
  `552bef4d5` (`falsify.py` and the five provider source files). `src` tree
  `c49199ce…` is the base's. The one differing file under
  `capsules/model-provider` is `tests/confine/main.rs`: the checkout has
  `14eebb4a…`, the base has `2f7797e3…`. No base entry names a test in it.
- Environment: `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`
  `CARGO_TARGET_DIR=capsules/model-provider/.022-replay/target`
  `CARGO_BUILD_BUILD_DIR=capsules/model-provider/.022-replay/build`
  `TMPDIR=/tmp/022-replay-tmp`; lease held for the whole run.
- Result: exit 0, wall time 151.33 s, `summary: 76 CAUGHT of 76`, and
  `not as expected` is absent. Counts: 76 CAUGHT, 0 SURVIVED, 0 NOT RUN,
  0 BUILD FAILED, 0 NO MATCH, 0 BACKUP TAKEN, 0 `CAUGHT (does not build)`,
  0 `SURVIVED (expected, by design)`.
- Raw reference: the per-entry block below, which is the run's stdout. Task 019's
  LOG entry records the same summary on commit `3c8b4d2b1`, whose runner is
  `650e25ae…` and whose model list is `b26dc734…`.

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
PV57=CAUGHT PV58=CAUGHT PV59=CAUGHT PV60=CAUGHT
summary: 76 CAUGHT of 76
```

Replay method note: a copy of the base runner placed one directory away from its
own path produced `PV09 = NOT RUN` and `PV10 = SURVIVED`, because those two
entries read `HERE` and `DATA`. That run is discarded and is not evidence. The
accepted replay keeps the runner at its own path so both entries see the same
paths as at the base.

### Candidate side

- Runner `f4a9748d…`, list `f763b203…`, 80 entries; source `7b2e8ee31` with the
  same `src` (`c49199ce…`), tests (`14eebb4a…`) and `examples/agent-host` tree as
  the receipt commit `118d42d3a`. The receipt is therefore a valid execution of
  the tested candidate on every path the model list touches.
- Receipt: task 021's base run, recorded in
  [r1-lab-runner-model.md](r1-lab-runner-model.md) ("Model list, before the
  edit"): `summary: 80 CAUGHT of 80`, exit 0, wall time 134.93 s, with the same
  lease and the same environment shape. Task 020's own LOG entry records
  `summary: 80 CAUGHT of 80` and `cargo test` exit 0 on its branch.
- Counts: 80 CAUGHT, 0 of every other outcome.

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
summary: 80 CAUGHT of 80
```

### Comparison

- 60 pre-existing `selftest` entries and 16 pre-existing `provider` entries keep
  their id, command, expectation, named tests and `CAUGHT` verdict.
- Added entries, all `CAUGHT`, explaining 76 to 80:

| Added | Rule the mutation plants | Named test that fails | Verdict |
| --- | --- | --- | --- |
| `PV61` | the loader check runs after each failed test's own section is removed | `a loader error inside a section is not a catch` | CAUGHT |
| `PV62` | the Cargo failure check runs after that removal | `a cargo failure inside a section is not a catch` | CAUGHT |
| `PV63` | a section header matches with trailing text | `the section header is an exact line` | CAUGHT |
| `PV64` | a section closes at a line that ends with the closing delimiter | `the closing delimiter is an exact line` | CAUGHT |

- One title-only change: `PV60` keeps its mutation, named tests and verdict, and
  its title now reads "the closing delimiter may carry text after it". This is a
  label correction, not an anchor retarget.
- No entry was removed.

## Pair 2: 021's base against its tested candidate (model list)

- Base side: `118d42d3a`, runner `f4a9748d…`, list `f763b203…`, 80 entries. The
  same receipt as pair 1's candidate: `summary: 80 CAUGHT of 80`, exit 0,
  134.93 s. This run is at the base commit itself, not a replay.
- Candidate side: tested at `118d42d3a` plus the two intended edits, with runner
  `54308b2c…` and list `6040948e…`; the same bytes are committed at `492677d78`
  and at the merged head `9f8c7d197`. Receipt
  [r1-lab-runner-model.md](r1-lab-runner-model.md) ("Model list, after the
  edit"): `summary: 90 CAUGHT of 90`, exit 0; the after run and the self-test
  together took 132.01 s.

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
summary: 90 CAUGHT of 90
```

### Comparison

- 64 pre-existing `selftest` entries and 16 pre-existing `provider` entries keep
  their id, rule, named tests and `CAUGHT` verdict.
- Added entries, all `CAUGHT`, explaining 80 to 90:

| Added | Rule the mutation plants | Named test that fails | Verdict |
| --- | --- | --- | --- |
| `PV65` | `lab` is not a registered command | `provider spec uses locked manifest` | CAUGHT |
| `PV66` | the `lab` command builds the capsule-identity manifest | `provider spec uses locked manifest` | CAUGHT |
| `PV67` | the `lab` command omits its workspace selection | `provider spec uses locked manifest` | CAUGHT |
| `PV68` | the `provider` command gains the lab's workspace selection | `provider spec uses locked manifest` | CAUGHT |
| `PV69` | startup recovery skips the lab capsule's source | `a killed provider edit is recovered` | CAUGHT |
| `PV70` | startup recovery skips the lab's build script | `a killed provider edit is recovered` | CAUGHT |
| `PV71` | startup recovery skips the lab's name rule | `a killed provider edit is recovered` | CAUGHT |
| `PV72` | startup recovery skips the audit crate's manifest | `a killed provider edit is recovered` | CAUGHT |
| `PV73` | startup recovery skips the audit crate's interface document | `a killed provider edit is recovered` | CAUGHT |
| `PV74` | startup recovery skips the audit crate's source | `a killed provider edit is recovered` | CAUGHT |

- Anchor-only retargets: five pre-existing entries keep their id, mutation,
  named tests, expectation and verdict, and their `old`/`new` text now names the
  table-shaped lines:

| Id | Anchor before | Anchor after |
| --- | --- | --- |
| `PV11` | `spec()` cargo line naming `PROVIDER_CRATES[command]` | the same line naming `crate_manifest` |
| `PV14` | the same line | the same line |
| `PV17` | the same line | the same line |
| `PV43` | `"did": REPO / ...` table row | `"did": (REPO / ..., ())` row |
| `PV50` | `"capsule-identity": REPO / ...` row | `"capsule-identity": (..., ())` row |

- No entry was removed, and every added entry is `CAUGHT`.

## DID and wallet lists: BLOCKED

Both lists are byte-identical at every side, so their pair isolates the runner.
The task gives those runs to the confine owner or to a supervisor with explicit
authorization, because their mutations cross this lane's paths. The builder did
not run them, and this repository holds no full-execution receipt for either list
at any of the four sides.

| Side | Runner | DID list / source tree | Wallet list / source tree | Full run receipt |
| --- | --- | --- | --- | --- |
| 020 base `552bef4d5` | `650e25ae…` | `feffe9f9…` (21) / `adaadfc2…` | `f2cbc08f…` (27) / `5962f9ba…` | none in this repository |
| 020 candidate `7b2e8ee31` | `f4a9748d…` | `feffe9f9…` (21) / `adaadfc2…` | `f2cbc08f…` (27) / `5962f9ba…` | none |
| 021 base `118d42d3a` | `f4a9748d…` | `feffe9f9…` (21) / `d919b59b…` | `f2cbc08f…` (27) / `7ae754d8…` | none |
| 021 candidate `9f8c7d197` | `54308b2c…` | `feffe9f9…` (21) / `d0aa5d8c…` | `f2cbc08f…` (27) / `2a4259a9…` | none |

Prior confine evidence, and why it is not accepted here: task 034 merged as
private PR #149 at `4010c144c` (commit timestamp 26 Oct 11:09 +0800; the task
names 10:09). Its merge commit is an ancestor of the 020 base, and its DID and
wallet trees (`adaadfc2…`, `5962f9ba…`), runner (`650e25ae…`) and both lists match
the 020 base exactly. It is therefore useful prior evidence for the base side and
proves nothing about either candidate, because 020 and 021 changed the runner.
Its raw record (per-entry output, exit code, environment, restoration) is not in
this repository, so this report cannot check it entry by entry. The owner must
supply that record for the base side, or rerun; the two candidate sides need
new runs in any case.

Missing runs and their owners:

| Missing run | Exact source, list and command | Next owner |
| --- | --- | --- |
| DID, pair 1 base | `552bef4d5` (or the 034 receipt above), runner `650e25ae…`, `--from capsules/did-provider/falsifiers.json` (21 entries) | confine owner |
| Wallet, pair 1 base | `552bef4d5`, runner `650e25ae…`, `--from capsules/wallet-provider/falsifiers.json` (27 entries) | confine owner |
| DID, pair 1 candidate | `7b2e8ee31` / `118d42d3a`, runner `f4a9748d…`, same list | confine owner |
| Wallet, pair 1 candidate | `7b2e8ee31` / `118d42d3a`, runner `f4a9748d…`, same list | confine owner |
| DID, pair 2 candidate | `9f8c7d197`, runner `54308b2c…`, same list, source tree `d0aa5d8c…` | confine owner |
| Wallet, pair 2 candidate | `9f8c7d197`, runner `54308b2c…`, same list, source tree `2a4259a9…` | confine owner |

Each run needs `/usr/bin/sandbox-exec` present (it is present on this Mac), the
full list, the per-entry output, the exit code, and restoration evidence. On a
host without that tool the sandbox entries read `SURVIVED` and prove nothing.

## R1 lab lists: BLOCKED

The runner-side part of R1 exists at `54308b2c…`: `lab` is a registered command
that builds and runs `cargo test --locked --manifest-path
lab/wasm-capsule/Cargo.toml --workspace`, and both lab lists load and display
(exit 0). These are load checks, not executions:

| List | SHA-256 | Entries | Load check | Full run |
| --- | --- | --- | --- | --- |
| `lab/wasm-capsule/falsifiers.json` | `dc21f858…` | 16 | exit 0, 16 lines | none |
| `lab/wasm-capsule/audit/falsifiers.json` | `ee017191…` | 49 | exit 0, 49 lines | none |

The root list changed after R1's tested source: at `118d42d3a` it was
`6991fd5e…` with 33 entries, and task `5b9b1a677` (wasm-capsule-lab 010, merged
through PR #161) replaced that with the current 16 entries. The audit list is
unchanged from R1. The owners' documents still say the canonical runner awaits
R1 and that no entry is runner-caught, so the hand proofs stay separate from
runner execution counts.

Missing runs and their owners:

| Missing run | Exact command | Next owner |
| --- | --- | --- |
| Lab root, current list `dc21f858…` (16) | `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json` | Wasm lab owner |
| Lab audit, current list `ee017191…` (49) | `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/audit/falsifiers.json` | audit owner |

A caught runtime-test entry needs all its named tests to have run and failed; a
`compile_error` or declared-survivor entry keeps the runner's existing meaning.
Any failure, missing run or unexpected outcome keeps the R1 gate open with that
id, its reason and its lane. No such receipt exists here, so the gate stays open.

## Supervisor default list: BLOCKED

The default list is `examples/agent-host/falsifiers.json`, `d79e9bcf…`, 144
entries, and it is the supervisor's existing gate. This report ran only a display
check (`--list`, exit 0, 144 lines) and a `--list` with a path token, which the
runner treats as an id filter and which therefore printed the default list rather
than the model list. Neither is an execution. The supervisor supplies the full
run at `54308b2c…` and this candidate; Flint routes it.

## Provider suites, sandbox and skips

| Source | Runner | Command | Result |
| --- | --- | --- | --- |
| `9f8c7d197` (this source) | `54308b2c…` | `cargo fmt --manifest-path capsules/model-provider/Cargo.toml -- --check` | exit 0 |
| `9f8c7d197` | `54308b2c…` | `cargo test --locked --manifest-path capsules/model-provider/Cargo.toml` | exit 0: lib 299 passed, 0 failed, 2 ignored; `tests/confine/main.rs` 17 passed; `tests/process.rs` 8 passed; doc-tests 0 |
| `9f8c7d197` | `54308b2c…` | `python3 -I examples/agent-host/falsify.py --self-test` | `self-test: OK`, exit 0 |
| `118d42d3a` (both candidate sides) | `f4a9748d…` | the same suite, per [r1-lab-runner-model.md](r1-lab-runner-model.md) | 299 passed, 2 ignored; 17 passed; 8 passed |
| `3c8b4d2b1` (019 receipt for the base lineage) | `650e25ae…` | the same suite | 299 passed, 2 ignored; 10 passed; 8 passed |

The two ignored lib tests are the merged opt-in real-model tests; they need a
live model service and are skipped by design. No sandbox test skipped on this
Mac: `/usr/bin/sandbox-exec` is present and the 17 confinement tests ran.

Missing suite receipt: the 020 base's own test source (`552bef4d5`,
`tests/confine/main.rs` `2f7797e3…`) has no recorded suite run. The 019 receipt
covers its source with a different harness (`db61d843…`), and this source's
receipt covers `14eebb4a…`. A clean run at the base's exact harness is the only
remaining suite gap; the provider builder or the supervisor can supply it.

## Restoration evidence

Accepted replay (provider builder's own record):

- The runner was written with base bytes `650e25ae…` and restored to head bytes
  `54308b2c…` in the same process, verified by SHA-256 before and after.
- Every source file the list edits kept its pre-run SHA-256:
  `local_memory.rs` `693b26b4…`, `journal.rs` `7b0a6855…`, `contract.rs`
  `d456018e…`, `local_llama.rs` `3c66b39f…`, `adapters.rs` `4213b8bc…`; the list
  stayed `6040948e…`.
- No `*.falsify-original` remained anywhere in the repository, and no
  `.falsify-selftest` directory remained.
- The run's build and test scratch (`.022-replay/`, `/tmp/022-replay-tmp`) was
  removed after the record was written, together with the empty
  `capsules/model-provider/handoff/reports` directories that the discarded
  relocated attempt left; no provider, engine or cargo process from the run
  remained.
- `git status --short` was clean before the replay. During it the tracked tree
  stayed clean and only the untracked scratch appeared; after cleanup only this
  report and its LOG line remain.

Other sides: task 021's record states that `git status --short` showed only the
two intended files after each run and that the cargo scratch folders were
removed; task 020's record states the same. DID, wallet and lab owner records are
missing, so their restoration evidence is part of the blocker above.

## Grade, R1 and the wind-down boundary

No grade row moves. The proved total stays 46 of 70
([grade-rescore-3.md](grade-rescore-3.md)): row 10 stays 5, row 12 stays 4, row
14 stays 1. The runner-side R1 change is merged and its lists load, but the runs
that would complete R1's proof are missing, so R1 does not yet unblock row 14's
package-identity tooling and this proof does not close the gate.

The wind-down boundary stays where it is: R1 and this proof must both merge
before Flint adds STOP and review capacity moves to M1. Further tasks need a new
Sasha instruction; no task is created here.

## Principles

1. **Named by hash:** yes. Every code, list and runner claim is bound to a commit,
   tree or SHA-256; the report adds no name or URL as identity (this file, the
   identity tables).
2. **No ambient authority:** yes. Docs only; no capsule, Home, UI, network, file
   or hardware authority changes anywhere in this task.
3. **One path (P10):** yes. One runner (`examples/agent-host/falsify.py`) and one
   list per owner; the replay reused the base runner's own bytes and left no
   second runner, and the report adds no second list, gate or parser.
4. **Trusted core:** yes. No Runtime, provider or capsule code changed; the work
   is a proof record in the lane's own report folder.
5. **Fails closed (P11):** yes. A run without a checkable receipt is `BLOCKED`
   with its exact source, list, run and owner instead of a claimed pass.
6. **Self-contained (Rong):** yes. No capsule changed; the proof observes the
   provider's own tests and the runner's own entries.
7. **Tests prove it:** yes for the existing rules. This task adds no rule, test or
   falsifier (out of scope), and the report states exactly which named tests ran,
   under which runner and list bytes, instead of asserting a rule from source.
8. **Separate decisions:** yes. Identity (commit, tree, SHA-256), admission (no
   new admission anywhere) and allowance (no resource budget change) stay three
   separate facts, and no one implies another.

## Validation of this record

- Every link above is a path in this repository and exists.
- `git diff --check` is clean.
- The lane checks for this task pass on this source: format check exit 0, provider
  suite exit 0, self-test `OK`, and the display checks exit 0.
- `git status --short` shows only this report and the LOG line.

## Missing receipts and next owner

| Missing | Detail | Next owner |
| --- | --- | --- |
| DID full run, both candidate sides | runner `f4a9748d…` at `7b2e8ee31`, runner `54308b2c…` at `9f8c7d197`; list `feffe9f9…` (21) | confine owner |
| Wallet full run, both candidate sides | same runners; list `f2cbc08f…` (27) | confine owner |
| DID and wallet base-side raw record | runner `650e25ae…` at the 020 base, or the 034 receipt with per-entry output, exit code, environment and restoration | confine owner |
| Base-side DID and wallet runs, if the 034 record cannot be supplied | same as the two rows above | confine owner |
| Lab root list full run | runner `54308b2c…`, list `dc21f858…` (16) | Wasm lab owner |
| Lab audit list full run | runner `54308b2c…`, list `ee017191…` (49) | audit owner |
| Supervisor default list full run | runner `54308b2c…`, list `d79e9bcf…` (144) | supervisor |
| Base test-source suite receipt | `552bef4d5`, `tests/confine/main.rs` `2f7797e3…` | provider builder or supervisor |

The overall result stays **BLOCKED** until those receipts exist. The model
comparisons in this record need no rerun: their runner, list and test-source
identities match exactly, and every entry kept its verdict.
