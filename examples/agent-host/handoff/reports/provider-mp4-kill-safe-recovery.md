# MP4 proof: kill-safe recovery of provider edits

```text
Slice:        task 033 (proof only: no runner, list, test, provider or grade change)
Lane:         provider
Base:         042cb132371f77ce1b469af059e054bb7ef78295 (git rev-parse HEAD)
Branch:       spark/provider/033-mp4-kill-safe-recovery-proof-report
Machine:      macOS 26.5.2, Darwin 25.5.0 arm64; Python 3.9.6; cargo 1.91.0
              (ea2d97820 2025-10-10); rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      this report, plus one line in examples/agent-host/handoff/LOG.md
Grade:        unchanged
```

This base includes task 036 (merge `e3f510722b4c87df089e14be0dfafd30a27e6322`,
PR #308), which carries task 032's reviewed files. The runner at this head adds
the case `a runner killed in its test step is recovered`, and
`capsules/model-provider/falsifiers.json` holds 136 entries, PV115 and PV116
included. The branch's upstream ref `spike/spike/agent-host` was three confine
commits ahead at run time (`ef1b343c5`), touching only did-provider and
wallet-provider confinement files; this lane's files and every command below
read the tree at `042cb13`.

`RUST_TEST_THREADS` and `CARGO_INCREMENTAL` change only the speed and
parallelism of a run. They change no verdict, no edit, no named test and no
restored byte.

The earlier whole-list run at `f92fe8597` (task 030) read
`summary: 134 CAUGHT of 134`. It is cited as an earlier run, not as this
task's evidence.

## Run 1: the two killed-edit self-test cases

Command as run. Date and time: 2026-10-27, 02:29:09 +0700.

```bash
python3 -I examples/agent-host/falsify.py --self-test-case "a runner killed in its test step is recovered"
```

```text
recovered capsules/model-provider/src/local_llama.rs from a killed run
MP01   provider caught        a synthetic local_llama edit
self-test: runner kill provider: exit=-9, calls=original:build,original:list,original:test,mutated:build,mutated:list,mutated:test, planted=True, restart=0, restored=True, leftovers=[]
recovered capsules/model-provider/src/local_llama.rs from a killed run
self-test: runner kill default: exit=-9, calls=original:build,original:list,original:test,mutated:build,mutated:list,mutated:test, planted=True, restart=0, restored=True, leftovers=[]
self-test case 'a runner killed in its test step is recovered': OK
exit=0
```

`exit=-9` is SIGKILL. The `calls` sequence shows the kill after the baseline
(`original:test`) and the rewrite (`mutated:build`, `mutated:list`) and before
any restore (`mutated:test` is where the runner kills itself). `planted=True`
reports the mutated target and the original backup in place at kill time;
`restart=0, restored=True, leftovers=[]` report the next run through `main()`:
exit 0, original bytes back, no backup and no temporary file beside the target.
Both startup modes read the same lines. The case prints the planted byte
strings themselves nowhere; the boolean is its evidence.

Command as run. Date and time: 2026-10-27, 02:27:54 +0700.

```bash
python3 -I examples/agent-host/falsify.py --self-test-case "a killed provider edit is recovered"
```

```text
recovered capsules/did-provider/confine.sb from a killed run
recovered capsules/did-provider/src/main.rs from a killed run
recovered capsules/did-provider/tests/confine.rs from a killed run
recovered capsules/model-provider/confine.sb from a killed run
recovered capsules/model-provider/src/adapters.rs from a killed run
recovered capsules/model-provider/src/contract.rs from a killed run
recovered capsules/model-provider/src/journal.rs from a killed run
recovered capsules/model-provider/src/local_llama.rs from a killed run
recovered capsules/model-provider/src/local_memory.rs from a killed run
recovered capsules/model-provider/tests/confine/main.rs from a killed run
recovered capsules/wallet-provider/confine.sb from a killed run
recovered capsules/wallet-provider/src/main.rs from a killed run
recovered capsules/wallet-provider/src/tests/falsifiers.rs from a killed run
recovered capsules/wallet-provider/tests/confine.rs from a killed run
recovered examples/agent-host/owned.txt from a killed run
recovered lab/capsule-identity/.gitignore from a killed run
recovered lab/capsule-identity/README.md from a killed run
recovered lab/capsule-identity/fixtures/wc001-core/capsule.json from a killed run
recovered lab/capsule-identity/src/lib.rs from a killed run
recovered lab/capsule-identity/tests/common/mod.rs from a killed run
recovered lab/wasm-capsule/.gitignore from a killed run
recovered lab/wasm-capsule/LOG.md from a killed run
recovered lab/wasm-capsule/README.md from a killed run
recovered lab/wasm-capsule/audit/Cargo.toml from a killed run
recovered lab/wasm-capsule/audit/INTERFACE.md from a killed run
recovered lab/wasm-capsule/audit/src/lib.rs from a killed run
recovered lab/wasm-capsule/capsule/capsule.json from a killed run
recovered lab/wasm-capsule/capsule/src/lib.rs from a killed run
recovered lab/wasm-capsule/tests/common/build.rs from a killed run
recovered lab/wasm-capsule/tests/lab_cid.rs from a killed run
recovered lab/wasm-capsule/tests/verify.rs from a killed run
recovered lab/wasm-capsule/tools/build from a killed run
recovered lab/wasm-capsule/tools/src/bin/bundle.rs from a killed run
recovered lab/wasm-capsule/tools/src/bundle.rs from a killed run
recovered lab/wasm-capsule/tools/src/lab_name.rs from a killed run
recovered lab/wasm-capsule/tools/src/lib.rs from a killed run
recovered lab/wasm-capsule/tools/src/receipt.rs from a killed run
recovered lab/wasm-capsule/tools/src/run.rs from a killed run
recovered lab/wasm-capsule/tools/src/verify.rs from a killed run
MP01   provider caught        counted_input_tokens wraps an overflowing repeated prefix instead of refusing
MP02   provider caught        a finished run never arms the idle release
MP05   provider caught        the context check refuses only past the window, so the exact window runs
MP12   provider caught        a denied journal write is reported as journal-corrupt
MP15   provider caught        the replace step bypasses the shared journal write mapper
MP16   provider caught        the write step bypasses the shared journal write mapper
self-test: provider provider restart: exit=0, restored=True, foreign kept=True
recovered capsules/did-provider/confine.sb from a killed run
recovered capsules/did-provider/src/main.rs from a killed run
recovered capsules/did-provider/tests/confine.rs from a killed run
recovered capsules/model-provider/confine.sb from a killed run
recovered capsules/model-provider/src/adapters.rs from a killed run
recovered capsules/model-provider/src/contract.rs from a killed run
recovered capsules/model-provider/src/journal.rs from a killed run
recovered capsules/model-provider/src/local_llama.rs from a killed run
recovered capsules/model-provider/src/local_memory.rs from a killed run
recovered capsules/model-provider/tests/confine/main.rs from a killed run
recovered capsules/wallet-provider/confine.sb from a killed run
recovered capsules/wallet-provider/src/main.rs from a killed run
recovered capsules/wallet-provider/src/tests/falsifiers.rs from a killed run
recovered capsules/wallet-provider/tests/confine.rs from a killed run
recovered examples/agent-host/owned.txt from a killed run
recovered lab/capsule-identity/.gitignore from a killed run
recovered lab/capsule-identity/README.md from a killed run
recovered lab/capsule-identity/fixtures/wc001-core/capsule.json from a killed run
recovered lab/capsule-identity/src/lib.rs from a killed run
recovered lab/capsule-identity/tests/common/mod.rs from a killed run
recovered lab/wasm-capsule/.gitignore from a killed run
recovered lab/wasm-capsule/LOG.md from a killed run
recovered lab/wasm-capsule/README.md from a killed run
recovered lab/wasm-capsule/audit/Cargo.toml from a killed run
recovered lab/wasm-capsule/audit/INTERFACE.md from a killed run
recovered lab/wasm-capsule/audit/src/lib.rs from a killed run
recovered lab/wasm-capsule/capsule/capsule.json from a killed run
recovered lab/wasm-capsule/capsule/src/lib.rs from a killed run
recovered lab/wasm-capsule/tests/common/build.rs from a killed run
recovered lab/wasm-capsule/tests/lab_cid.rs from a killed run
recovered lab/wasm-capsule/tests/verify.rs from a killed run
recovered lab/wasm-capsule/tools/build from a killed run
recovered lab/wasm-capsule/tools/src/bin/bundle.rs from a killed run
recovered lab/wasm-capsule/tools/src/bundle.rs from a killed run
recovered lab/wasm-capsule/tools/src/lab_name.rs from a killed run
recovered lab/wasm-capsule/tools/src/lib.rs from a killed run
recovered lab/wasm-capsule/tools/src/receipt.rs from a killed run
recovered lab/wasm-capsule/tools/src/run.rs from a killed run
recovered lab/wasm-capsule/tools/src/verify.rs from a killed run
self-test: provider default restart: exit=0, restored=True, foreign kept=True
self-test case 'a killed provider edit is recovered': OK
exit=0
```

Each `recovered ... from a killed run` line is the next run putting one planted
original back. `restart: exit=0, restored=True, foreign kept=True` reports the
two checks for that mode: every target's bytes and mtime are back and its
backup is gone, while another owner's planted backup is untouched. The case
prints a kill line only when the plant fails, so its absence is the passing
evidence for the planted bytes.

## Run 2: the 18 ids that guard the three merged PRs and 036

Command as run, one command. Date and time: 2026-10-27, 02:29:13 +0700.

```bash
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json PV35 PV36 PV37 PV38 PV39 PV42 PV96 PV97 PV98 PV99 PV100 PV101 PV102 PV103 PV104 PV105 PV115 PV116
```

```text
baseline: 10 named tests pass without an edit, 0 do not
PV35   CAUGHT                             1s  a nested run restores a backup its caller still owns
PV36   CAUGHT                             1s  a nested run ignores --keep-backups and takes the caller's backup
PV37   CAUGHT                             0s  the backup is recorded before the link, so a collision consumes it
PV38   CAUGHT                             0s  the collision refusal is bypassed, so the caller's backup is consumed
PV39   CAUGHT                             1s  released local backups are inherited again from the published environment
PV42   CAUGHT                             1s  startup recovery skips the model provider's confinement profile
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
PV115  CAUGHT                             1s  startup recovery is skipped in main()
PV116  CAUGHT                             1s  startup recovery finds a backup but restores nothing
summary: 18 CAUGHT of 18
exit=0
```

All 18 ids read CAUGHT. Run wall time was 12.49 seconds. Every id's named tests
all failed under its planted bug, which is this lane's definition of CAUGHT.

## What each row holds

| PR or task | Rule it holds | Named test or tests | Falsifier ids | Verdict |
| --- | --- | --- | --- | --- |
| PR #73, task 011 | A nested run never restores a backup its caller still owns, `--keep-backups` included, and a backup or temporary file this run did not create is refused before any write | `a nested run keeps the caller's backup`, `a backup this run did not make is refused`, `released backups are recovered again` | PV35-PV39 | Run 2: 5 of 5 CAUGHT |
| PR #89, task 013 | The model provider's `confine.sb` is one exact startup-recovery target, so a killed edit to it is restored | `a killed provider edit is recovered` | PV42 | Run 2: CAUGHT |
| PR #228, task 028 | One edit-path rule refuses an absolute name, a folder outside REPO and a symbolic link before any link or write, and an entry with one outside edit changes no file | `an absolute edit path is refused`, `an edit path that climbs out is refused`, `an edit through a symbolic link is refused`, `an absent outside edit path gets the containment reason`, `an entry with one outside edit changes no file` | PV96-PV105 | Run 2: 10 of 10 CAUGHT |
| Task 036 (carries 032) | The runner killed through `main()` after the baseline and the rewrite, and before the restore, is recovered by the next run: original bytes, no backup, no temporary file, in both startup modes | `a runner killed in its test step is recovered`, `a killed provider edit is recovered` | PV115, PV116 | Run 1: both cases OK. Run 2: 2 of 2 CAUGHT |

The 036 row is the kill-safe case. The kill lands inside `main()` after the
baseline and the rewrite and before the restore, and this line shows it:

```text
self-test: runner kill provider: exit=-9, calls=original:build,original:list,original:test,mutated:build,mutated:list,mutated:test, planted=True, restart=0, restored=True, leftovers=[]
```

The `default` startup mode prints the same shape of line in Run 1.
PV115 removes startup recovery from `main()` and PV116 finds a backup but
restores nothing; both are CAUGHT by the two cases, so the case is not a
pass through a code path that never recovers.

## What MP4 evidence does not cover

- A file outside `PROVIDER_TARGETS` and outside `examples/agent-host` is not
  restored by this runner. `recover_backups()` restores the runner's own
  backups and those exact named targets only; anything else stays with its
  owner. This is BACKLOG item 8e, held.
- A tree changed during a run is not covered. The path rule decides on the tree
  as it stands when an entry starts, and a file changed by another writer
  between that decision and the restore is outside both the rule and the kill
  test. This is BACKLOG item 16, held.
- The kill test uses a stub for the cargo step. It proves the runner's
  recovery, not that a cargo build of the provider runs and restores
  correctly. A real cargo build is covered by the lane's `cargo test` gate,
  not by this case.

## Status after each run

```text
$ git status --short        # after Run 1, runner-kill case
$ git status --short        # after Run 1, killed-provider-edit case
$ git status --short        # after Run 2, 18 ids
```

Each command printed no line: no untracked folder, no `.falsify-*` file, no
changed file. The self-test scratch folder
`examples/agent-host/handoff/reports/.falsify-selftest` was gone after each
self-test case.

## Lane checks at this base

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path capsules/model-provider/Cargo.toml -- --check` | exit 0 |
| `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path capsules/model-provider/Cargo.toml` | exit 0: 301 passed + 2 ignored (lib), 25 passed (confine), 8 passed (process) - 334 passed, 2 ignored |
| `python3 -I examples/agent-host/falsify.py --self-test` | `self-test: OK`, exit 0 |
| `git diff --quiet 042cb13 -- examples/agent-host/falsify.py` | true: exit 0, so the default-list run is skipped and the runner is unchanged |
| `python3 -I examples/agent-host/falsify.py --list capsules/model-provider/falsifiers.json` | exit 0; the positional is an id filter, so this prints the default agent-host list (144 rows) |
| `python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json --list` | exit 0, 136 rows: the model list this report's ids come from |

The last row is the check that reads the model list; the lane's literal
`--list capsules/model-provider/falsifiers.json` form does not select it.

## Next owner

No id and no case needs a fix task. This report books no grade point and no M1
check itself; Flint books MP4 from it.

**MP4 evidence complete**
