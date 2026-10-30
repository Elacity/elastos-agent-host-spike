# macOS evidence pack

One morning command that runs the macOS M1 rows that have never been run on
Sash's Mac. It writes one work folder under `$HOME/mac-evidence-pack/` and one
`summary.txt`.

The pack creates its own clone under `$HOME/mac-evidence-pack/pack-clone`.
It refuses that path if it already holds something the pack did not create.
It never runs a changing git command in any other directory.

The pack calls the existing runners. It does not reimplement them. Live rows
need native arm64 macOS. This Linux VM marks every macOS row **NOT RUN**.

## What Sash types

Do not `cd` into the spike clone. Do not `git checkout` or `git fetch` there.

From a copy of this folder (a browser download of `lab/mac-evidence-pack/`
from draft PR #359, a USB copy, or the pack-owned clone):

```bash
sh lab/mac-evidence-pack/morning.sh
cat "$(ls -dt "$HOME/mac-evidence-pack/"*/summary.txt | head -1)"
```

`morning.sh` creates `$HOME/mac-evidence-pack/pack-clone` or exits with
`PACK_CLONE_FOREIGN` if that path already holds something this pack did not
create. A refused or aborted run still writes `summary.txt`.

Stop if `lab/mac-evidence-pack/morning.sh` is missing.

## What it runs

Pins live in `pins.ini` (row → branch + SHA). The pack prints each SHA in
`summary.txt` and verifies an `ok` pin exists before that row runs. A pin
that is missing, superseded, or `NEEDS_REPIN` is **FAIL** with that named
reason, never PASS.

| Row | Draft PR | Branch | Pin |
| --- | --- | --- | --- |
| A8 | #301 | `cursor/a1-a8-hardening-85ce` | `ok` |
| C1–C7 | #323 | `cursor/redteam-fix-4bfb` | `NEEDS_REPIN` (failed adversarial review #352; do not guess a new SHA) |
| A6 | #343 | `cursor/a6-a12-evidence-fix-6e3b` | `ok`, isolated temp root or `A12_SHARED_TMP_UNREDIRECTABLE` |
| A12 | #343 | same | same |
| A14 | #289 | `cursor/demo-a14-installed-demo-83e1` | `ok`, preflight only |

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
against `fixtures/`. It does not run the macOS rows. It does not clone.

## Pack tests

```bash
python3 -I -m unittest discover -s lab/mac-evidence-pack/tests -v
python3 -I lab/mac-evidence-pack/falsify.py
```
