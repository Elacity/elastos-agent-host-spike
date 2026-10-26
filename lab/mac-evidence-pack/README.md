# macOS evidence pack

One morning command that runs the macOS M1 rows that have never been run on
Sash's Mac. It writes one work folder under `$HOME/mac-evidence-pack/` and one
`summary.txt`.

The pack calls the existing runners. It does not reimplement them. Live rows
need native arm64 macOS. This Linux VM marks every macOS row **NOT RUN**.

## What Sash types

From the clone you already have (for example
`/Users/sash/code/wt-agent-host` or `~/code/elastos-agent-host-spike`):

```bash
cd /path/to/elastos-agent-host-spike
git fetch origin cursor/mac-evidence-pack-be32
git checkout cursor/mac-evidence-pack-be32
sh lab/mac-evidence-pack/run.sh
cat "$(ls -dt "$HOME/mac-evidence-pack/"*/summary.txt | head -1)"
```

Stop if `lab/mac-evidence-pack/run.sh` is missing. The run stays inside
`$HOME/mac-evidence-pack/<stamp>/`. It fetches only this repository. It does
not delete anything outside that folder.

## What it runs

| Row | Draft PR | Branch | Commit | Existing command |
| --- | --- | --- | --- | --- |
| A8 | #301 | `cursor/a1-a8-hardening-85ce` | `1a82d25bdd00d3a383433de84e97c39a4184d107` | `lab/a1-a8-hardening/run.sh` |
| C1–C7 | #323 | `cursor/redteam-fix-4bfb` | `fa1841f35d32e7bea98e124fd406231d0088fd4e` | named `cargo test` on that commit |
| A6 | #343 | `cursor/a6-a12-evidence-fix-6e3b` | `011d01f283a3f4ed4717383ecedf55622d451b4d` | `lab/a6-a12-evidence-fix/run.sh` then the A6 ThrowawayHome journeys |
| A12 | #343 | same | same | `run.sh` then `cleanup_census_refuses_each_leftover` |
| A14 | #289 | `cursor/demo-a14-installed-demo-83e1` | `39b4b47edc64d8705a0294c978e6171819cea9fc` | `lab/demo-a14/preflight.sh` only |

A14 does not install or run the demo. The summary points at
`lab/demo-a14/RUNBOOK.md` steps 3–5 on that branch.

Each row prints `PASS`, `FAIL`, or `NOT RUN` with a reason and the evidence
file. A refused preflight or a crashed row still writes `summary.txt`.

## Preflight

The pack checks macOS version, native arm64, Rosetta, uid 0, Xcode, cargo,
git, python3, sandbox-exec, spaces in HOME or the work path, and 14 GiB free.
A Rosetta shell is refused. Root is refused.

## Dry run on Linux

```bash
python3 -I lab/mac-evidence-pack/pack.py --dry-run
```

That prints the plan and the pinned commits. It runs the preflight logic
against `fixtures/`. It does not run the macOS rows.

## Pack tests

```bash
python3 -I -m unittest discover -s lab/mac-evidence-pack/tests -v
python3 -I lab/mac-evidence-pack/falsify.py
```
