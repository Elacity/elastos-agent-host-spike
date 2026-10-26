# Replay of the PV ids that 024, 027, 028 and 029 added

```text
Slice:        task 030 (proof only: no runner, list, test, provider or grade change)
Lane:         provider
Base:         f92fe85970ad0898be4f5247cf580b1f5eaf4bda (git rev-parse HEAD)
Branch:       spark/provider/030-run-the-pv-ids-merged-before-the-gate
Machine:      macOS 26.5.2, Darwin 25.5.0 arm64; Python 3.9.6; cargo 1.91.0
              (ea2d97820 2025-10-10); rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      this report, plus one line in examples/agent-host/handoff/LOG.md
Grade:        unchanged
```

## What this run shows

The 20:06 gate runs the ids a task's diff adds. Tasks 027, 024, 028 and 029
merged before that gate was live, so one runner run over their 35 ids was not
recorded. This report holds that run at the task base. The runner is
`examples/agent-host/falsify.py`; the list is
`capsules/model-provider/falsifiers.json`.

At this base the list holds 134 entries. The ids PV75 to PV109 exist once each,
with no gap, and each title matches the task that added it:

- 027: PV75-PV84, startup recovery targets for the wasm lab (10 ids);
- 024: PV85-PV95, the baseline before the first edit (11 ids);
- 028: PV96-PV105, the edit-path rule (10 ids);
- 029: PV106-PV109, the temporary file owned by this run (4 ids).

## Run 1: the 35 ids in one command

Command as run. Date and time: 2026-10-26, 22:55:52 +07 to 23:04:09 +07. The
command ran twice in that window and both runs read the same verdicts; the
lines below are from the second run, whose `git status` is quoted below.

```bash
CARGO_TARGET_DIR="$PWD/examples/agent-host/handoff/reports/.cargo-target" \
CARGO_BUILD_BUILD_DIR="$PWD/examples/agent-host/handoff/reports/.cargo-build" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json \
  PV75 PV76 PV77 PV78 PV79 PV80 PV81 PV82 PV83 PV84 \
  PV85 PV86 PV87 PV88 PV89 PV90 PV91 PV92 PV93 PV94 PV95 \
  PV96 PV97 PV98 PV99 PV100 PV101 PV102 PV103 PV104 PV105 \
  PV106 PV107 PV108 PV109
```

```text
baseline: 14 named tests pass without an edit, 0 do not
```

### 027: PV75-PV84

```text
PV75   CAUGHT                             1s  startup recovery skips the lab's .gitignore
PV76   CAUGHT                             1s  startup recovery skips the lab's README.md
PV77   CAUGHT                             1s  startup recovery skips the lab's capsule manifest
PV78   CAUGHT                             1s  startup recovery skips the lab's test build script
PV79   CAUGHT                             1s  startup recovery skips the lab's verify test
PV80   CAUGHT                             1s  startup recovery skips the lab's bundle binary
PV81   CAUGHT                             1s  startup recovery skips the lab's bundle module
PV82   CAUGHT                             1s  startup recovery skips the lab's tools source
PV83   CAUGHT                             1s  startup recovery skips the lab's verify tool
PV84   CAUGHT                             1s  startup recovery skips the lab's LOG.md
```

### 024: PV85-PV95

```text
PV85   CAUGHT                             1s  the baseline is skipped, so no named test is proved to pass without the edit
PV86   CAUGHT                             1s  a baseline outcome of failed is accepted as passed
PV87   CAUGHT                             0s  the unmutated build failure is ignored for compile_error entries
PV88   CAUGHT                             0s  a baseline outcome of not run is accepted as passed
PV89   CAUGHT                             2s  the baseline guard is bypassed for survives entries
PV90   CAUGHT                             0s  the baseline keeps duplicate named tests instead of one pair
PV91   CAUGHT                             0s  the baseline merges every command's named tests into one command
PV92   CAUGHT                             0s  the baseline runs each entry's named tests separately instead of once per command
PV93   CAUGHT                             0s  the baseline runs again before each entry instead of once before the first edit
PV94   CAUGHT                             1s  the entry is mutated before the baseline refuses it
PV95   CAUGHT                             0s  the baseline skips its free-space check before building
```

### 028: PV96-PV105

```text
PV96   CAUGHT                             0s  the three edit-path refusals are removed whole
PV97   CAUGHT                             0s  the absolute edit path check is removed, so an inside absolute path is accepted
PV98   CAUGHT                             0s  the containment check tests REPO.parent, so a climbing path is accepted
PV99   CAUGHT                             0s  the folder resolve is a lexical normalisation, so a folder link is not followed
PV100  CAUGHT                             0s  the symbolic-link check is removed
PV101  CAUGHT                             0s  the containment check runs after the missing-file check
PV102  CAUGHT                             0s  the containment refusal skips the file instead of raising
PV103  CAUGHT                             0s  the symbolic-link check accepts a dangling link
PV104  CAUGHT                             0s  the symbolic-link check accepts a link whose target is inside REPO
PV105  CAUGHT                             0s  the containment check runs only after the outside file is written
```

### 029: PV106-PV109

```text
PV106  CAUGHT                             0s  the temporary file is written through a truncating open, so a planted name is changed
PV107  CAUGHT                             0s  the cleanup removes the temporary file whoever created it
PV108  CAUGHT                             0s  the temporary file is made after the backup link, so a refusal leaves the backup behind
PV109  CAUGHT                             0s  the cleanup after a backup refusal is skipped, so this run's temporary file is left
```

```text
summary: 35 CAUGHT of 35
```

Every id read CAUGHT. Run wall time was 22.18 seconds.

## Run 2: the whole model list once

Command as run, in the same window:

```bash
CARGO_TARGET_DIR="$PWD/examples/agent-host/handoff/reports/.cargo-target" \
CARGO_BUILD_BUILD_DIR="$PWD/examples/agent-host/handoff/reports/.cargo-build" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json
```

```text
baseline: 62 named tests pass without an edit, 0 do not
summary: 134 CAUGHT of 134
```

The list holds 134 entries, so all 134 read CAUGHT. Run wall time was 289.33
seconds.

## What each review ask needed

| Task | PR | Ids | CAUGHT | Review ask | State |
| --- | --- | --- | --- | --- | --- |
| 024 | #204 | PV85-PV95 | 11 of 11 | Claude: "the supervisor's merge evidence should include a fresh full `--from capsules/model-provider/falsifiers.json` run at HEAD". Codex: "Record the full 115-entry model-list run for this HEAD" | Ids answered by this run. The full-list part is answered by run 2 at this HEAD: 134 entries, all CAUGHT. The entry count is 134 because later tasks added entries after 024; the 115-entry count was the list at 024's merge. |
| 027 | #194 | PV75-PV84 | 10 of 10 | Codex: add "the exact coverage-check command, printed results, and per-run status" | Answered by this run: the command is above, each printed result line is above, and each id's status is CAUGHT. |
| 028 | #228 | PV96-PV105 | 10 of 10 | The LOG line of 028 records a builder run only | Answered by this run for these ids: the printed result lines above are from the one runner at this base. |
| 029 | #236 | PV106-PV109 | 4 of 4 | The LOG line of 029 records a builder run only. Codex on 029: quote the literal result lines, not `(...)` | Answered by this run: the four literal result lines above are copied as printed, with no `(...)`. |

Task 026 was the first provider task gated by the 20:06 new-id gate; its
PV110-PV114 all read CAUGHT in its round-1 gate. This builder cannot read that
gate log, so this quote is the planner's record, not a line from this run.

This task adds no falsifier id, so the 20:06 gate has no new id to run for it.
The planner states that the gate prints its skip line in that case; that line is
outside this builder's evidence.

## Status after each run

```text
$ git status --short        # after the full-list run, before the report was written
$ git status --short        # after the last ids run
```

Each command printed no line: no untracked folder, no `.falsify-*` file, and no
changed file. The cargo scratch paths given above were removed after each run. The
runner's own `--self-test` scratch folder under
`examples/agent-host/handoff/reports/.falsify-selftest` was also gone after the
self-test.

## Lane checks at this base

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path capsules/model-provider/Cargo.toml -- --check` | exit 0 |
| `cargo test --locked --manifest-path capsules/model-provider/Cargo.toml` with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0` | 329 passed (4 suites, 2 ignored) |
| `python3 -I examples/agent-host/falsify.py --self-test` | `self-test: OK`, exit 0 |
| `git diff --quiet f92fe85 -- examples/agent-host/falsify.py` | true: the default-list run is skipped, the runner is unchanged |
| `python3 -I examples/agent-host/falsify.py --list capsules/model-provider/falsifiers.json` | lists the same 134 entries, exit 0 |

## Next owner

No id needs a fix task. The planner marks BACKLOG item 9 after this report
merges.
