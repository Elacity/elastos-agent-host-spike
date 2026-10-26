# mac-evidence-pack

```text
Lane:         lab/mac-evidence-pack (this folder only)
Branch / PR:  cursor/mac-evidence-pack-be32  https://github.com/Elacity/elastos-agent-host-spike/pull/359
Commit:       fbaaff699193bfda656b2d4e62bb8164e0e214c0
Base:         spike/agent-host
Machine:      Linux x86_64 cloud VM, rustc 1.91.0, no sandbox-exec, no KVM
```

Draft only. Do not merge. Every macOS row is **NOT RUN** on this machine.

## Invariant

One operator command, on Sash's Mac, fetches the four draft-PR commits into
one work dir under `$HOME/mac-evidence-pack/`, runs the existing runner for
each row, and writes `summary.txt`. A skip is not a pass. Exit 0 without the
named evidence is FAIL. A refused preflight or a crashed row still writes the
summary. The pack deletes nothing outside that work dir.

## Rows and pins

| Row | PR | Branch | Commit | Existing command |
| --- | --- | --- | --- | --- |
| A8 | #301 | `cursor/a1-a8-hardening-85ce` | `1a82d25bdd00d3a383433de84e97c39a4184d107` | `lab/a1-a8-hardening/run.sh` |
| C1 | #323 | `cursor/redteam-fix-4bfb` | `fa1841f35d32e7bea98e124fd406231d0088fd4e` | `init_requires_storage_without_key` |
| C2 | #323 | same | same | nickname store + `init_reports_nickname_read_error` |
| C3 | #323 | same | same | `outside_write_denied`, `outside_read_denied` |
| C4 | #323 | same | same | `verify_did_recovery_under_profile` |
| C5 | #323 | same | same | `missing_storage_root_is_refused` |
| C6 | #323 | same | same | `confined_outside_write_is_denied`, `confined_outside_read_is_denied` |
| C7 | #323 | same | same | `model_provider_ops_under_profile`, `model_outside_write_denied` |
| A6 | #343 | `cursor/a6-a12-evidence-fix-6e3b` | `011d01f283a3f4ed4717383ecedf55622d451b4d` | `lab/a6-a12-evidence-fix/run.sh` plus the two A6 ThrowawayHome journeys |
| A12 | #343 | same | same | `run.sh` plus `cleanup_census_refuses_each_leftover` |
| A14 | #289 | `cursor/demo-a14-installed-demo-83e1` | `39b4b47edc64d8705a0294c978e6171819cea9fc` | `lab/demo-a14/preflight.sh` only |

## Tests run here

```text
python3 -I -m unittest discover -s lab/mac-evidence-pack/tests -v
  -> Ran 35 tests ... OK
python3 -I lab/mac-evidence-pack/falsify.py
  -> 7 CAUGHT of 7
git diff --check
  -> clean
```

## Falsifiers

| ID | Break | Named test |
| --- | --- | --- |
| F-ME-EVIDENCE | exit 0 with no evidence file becomes PASS | `test_exit_zero_without_evidence_is_fail` |
| F-ME-ROSETTA | drop the Rosetta refusal | `test_rosetta_fixture_is_refused` |
| F-ME-ROOT | drop the uid 0 refusal | `test_root_fixture_is_refused` |
| F-ME-SPACE | drop the space-in-path refusal | `test_spaced_path_fixture_is_refused` |
| F-ME-OUTSIDE | treat every path as inside the work dir | `test_refuses_delete_outside_work_dir` |
| F-ME-A14 | A14 command becomes `install.sh --sign` | `test_a14_does_not_run_the_demo` |
| F-ME-SUMMARY | write `summary.skipped.txt` instead of `summary.txt` | `test_summary_written_after_crash` |

## Not run here

All live macOS rows. No aarch64. No sandbox-exec. No ThrowawayHome. No A14
demo. `--dry-run` prints the pins and runs preflight against fixtures only.

## Commands for Sash

```bash
cd /path/to/elastos-agent-host-spike
git fetch origin cursor/mac-evidence-pack-be32
git checkout cursor/mac-evidence-pack-be32
sh lab/mac-evidence-pack/run.sh
cat "$(ls -dt "$HOME/mac-evidence-pack/"*/summary.txt | head -1)"
```

## Could not wire

- The live A8 / C3–C7 / A6 / A12 / A14-preflight commands on a Mac. This
  environment is Linux.
- `#343`'s `run.sh` still plants `/tmp/elastos/storage/...` as that lane's
  own A12 check. The pack does not delete that tree.
- `lab/review-323/` from #346/#352. Those are reviews of #323, not the C
  row runners.
- C1, C2 and C5 are the named unit tests on the #323 tree. They are not
  sandbox-exec rows. C3, C4, C6 and C7 are.

## Principles

- 6: this is an operator pack, not a user Home command.
- 10: each row calls the existing runner on the pinned commit.
- 11: preflight, Rosetta, root, missing evidence and ignored tests fail closed.
- 12: README, catalog pins, tests and the summary line agree.

## DeepSeek

none

## Next

Sash runs the five commands on the Mac and attaches `summary.txt`.
