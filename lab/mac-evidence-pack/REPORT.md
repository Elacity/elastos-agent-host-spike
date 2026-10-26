# mac-evidence-pack

```text
Lane:         lab/mac-evidence-pack (this folder only)
Branch / PR:  cursor/mac-evidence-pack-be32  https://github.com/Elacity/elastos-agent-host-spike/pull/359
Commit:       (this follow-up; see git rev-parse HEAD)
Base:         spike/agent-host
Machine:      Linux x86_64 cloud VM, rustc 1.91.0, no sandbox-exec, no KVM
```

Draft only. Do not merge. Every macOS row is **NOT RUN** on this machine.

## Invariant

One operator command, on Sash's Mac, creates a pack-owned clone under
`$HOME/mac-evidence-pack/pack-clone`, runs the existing runner for each row
whose pin is `ok`, and writes `summary.txt`. A skip is not a pass. A missing,
superseded, or `NEEDS_REPIN` pin is FAIL. #343 is FAIL unless its runner can
be redirected off `/tmp/elastos/storage`. A refused preflight, a foreign
clone, or a crashed row still writes the summary. Changing git runs only in
the pack-owned clone.

## CTO review fixes

1. Clone ownership. README no longer tells Sash to `git checkout` the spike
   tree. `morning.sh` / `pack.py --bootstrap` create `$HOME/mac-evidence-pack/pack-clone`
   or refuse with `PACK_CLONE_FOREIGN`. `owned_git` refuses `FOREIGN_CLONE`
   for any changing git command inside a repo that lacks the pack marker.
2. Pin file. Every row pin is in `pins.ini` (row → branch + SHA + status).
   C1–C7 stay on recorded SHA `fa1841f3` and are marked `NEEDS_REPIN`
   (adversarial review #352; #323 is being rewritten). The pack prints each
   SHA in `summary.txt`. `PIN_MISSING` / `PIN_NEEDS_REPIN` / `PIN_SUPERSEDED`
   are FAIL, never PASS. No new SHA was guessed.
3. #343 isolation. After checkout, the pack inspects
   `lab/a6-a12-evidence-fix`. That runner hardcodes `/tmp/elastos/storage`
   and has no `env::var("ELASTOS_TMP_ROOT"|...)`, so A6 and A12 FAIL
   `A12_SHARED_TMP_UNREDIRECTABLE` and the runner is not started. If a later
   pin grows an env redirect, the pack sets those vars to
   `<work>/isolated-tmp`.

## Tests run here

```text
python3 -I -m unittest discover -s lab/mac-evidence-pack/tests -v
  -> Ran 58 tests ... OK
python3 -I lab/mac-evidence-pack/falsify.py
  -> 13 CAUGHT of 13
python3 -I lab/mac-evidence-pack/pack.py --dry-run
  -> 11 rows NOT RUN, pins printed, summary.txt written
git diff --check
  -> clean
```

## Falsifiers

Each new guard has a planted-bug falsifier that must print CAUGHT.

| ID | Break | Named test |
| --- | --- | --- |
| F-ME-EVIDENCE | exit 0 with no evidence file becomes PASS | `test_exit_zero_without_evidence_is_fail` |
| F-ME-ROSETTA | drop the Rosetta refusal | `test_rosetta_fixture_is_refused` |
| F-ME-ROOT | drop the uid 0 refusal | `test_root_fixture_is_refused` |
| F-ME-SPACE | drop the space-in-path refusal | `test_spaced_path_fixture_is_refused` |
| F-ME-OUTSIDE | treat every path as inside the work dir | `test_refuses_delete_outside_work_dir` |
| F-ME-A14 | A14 command becomes `install.sh --sign` | `test_a14_does_not_run_the_demo` |
| F-ME-SUMMARY | write `summary.skipped.txt` instead of `summary.txt` | `test_summary_written_after_crash` |
| F-ME-FOREIGN-CLONE | `is_pack_owned` always true | `test_refuses_existing_non_pack_clone_path` |
| F-ME-PIN-REPIN | `NEEDS_REPIN` is runnable | `test_needs_repin_row_is_fail_not_pass` |
| F-ME-PIN-MISSING | empty SHA is runnable | `test_missing_pin_is_fail` |
| F-ME-PIN-SUPERSEDED | superseded is runnable | `test_superseded_pin_is_fail` |
| F-ME-A12-TMP | hardcoded `/tmp/elastos/storage` is treated as redirectable | `test_a12_unredirectable_is_fail_named_reason` |
| F-ME-ABORT-SUMMARY | abort path skips `summary.txt` | `test_foreign_pack_clone_writes_summary_and_refuses` |

## Not run here

All live macOS rows. No aarch64. No sandbox-exec. No ThrowawayHome. No A14
demo. `--dry-run` prints the pins and runs preflight against fixtures only.

## Commands for Sash

```bash
sh lab/mac-evidence-pack/morning.sh
cat "$(ls -dt "$HOME/mac-evidence-pack/"*/summary.txt | head -1)"
```

## Could not wire

- The live A8 / A14-preflight commands on a Mac. This environment is Linux.
- C1–C7 stay `NEEDS_REPIN`. A new #323 SHA is a later human edit of `pins.ini`.
- #343 `run.sh` hardcodes `/tmp/elastos/storage` with no env redirect, so the
  pack refuses that runner rather than planting the shared tree.
- `lab/review-323/` from #346/#352. Those are reviews of #323, not the C
  row runners.

## Principles

- 6: this is an operator pack, not a user Home command.
- 10: each row calls the existing runner on the pinned commit when the pin is `ok`.
- 11: preflight, foreign clones, bad pins, missing evidence and #343 shared tmp fail closed.
- 12: README, `pins.ini`, tests and the summary line agree.

## DeepSeek

none

## Next

Sash runs `morning.sh` on the Mac and attaches `summary.txt`. C1–C7 will FAIL
`PIN_NEEDS_REPIN` until `pins.ini` is re-pinned. A6/A12 will FAIL
`A12_SHARED_TMP_UNREDIRECTABLE` until #343 grows an env redirect.
