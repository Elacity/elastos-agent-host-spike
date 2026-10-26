Slice:        M1 check A14 morning runbook, PR 366 NO-GO fixes
Branch / PR:  cursor/demo-a14-installed-demo-83e1  https://github.com/Elacity/elastos-agent-host-spike/pull/289
Commit:       f721ec794f1fb4d17afc716459e6bbf006257093   parent 55814f9e80acfba9e27d3521dd0810f33d0ebdfd
              55814f9e80acfba9e27d3521dd0810f33d0ebdfd   parent 39b4b47edc64d8705a0294c978e6171819cea9fc
Base:         spike/agent-host. Stay on this branch. Draft. Do not merge.
Develop:      Elacity develop not fetched or merged.
Machine:      Linux x86_64 (cloud VM), rustc 1.91.0, Python 3.12.3, OpenSSH 9.6p1

A14 itself is NOT RUN. Only Sash's Mac run counts.

Read first: PR 366 `lab/review-a14-289/REVIEW.md` at a4fab5b8, head of PR 289 then 39b4b47e.

Invariant: the morning block clones a brand-new folder, stops on the first failed line, and never changes an existing tree. Install runs the same preflight as step 2. A write failure after --sign removes only the key this run created. Every install refusal and every run writes this run's summary.txt.

Refusals:
- destination folder already exists
- lab/demo-a14/install.sh missing after clone
- CARGO_TARGET_DIR that resolves outside the checkout, including ../elsewhere
- preflight missing: list (ssh-keygen, Xcode tools, crates.io, wasm target, ...)
- install write failure after this run created a signing key (key is removed)

Changed:
- lab/demo-a14/RUNBOOK.md - one set -euo pipefail block; git clone --branch into $HOME/a14-run-<timestamp>; refuse if dest exists; step 5 opens this-run/summary.txt
- lab/demo-a14/demo.py - preflight_problems is install's default ready; refuse_install writes summary; cargo_target_problem collapses ..; remove key this run created
- lab/demo-a14/preflight.sh - same outside-target rule; quarantine list includes preflight, journeys, RUNBOOK
- lab/demo-a14/tests/test_version_binding.py - new tests for each finding
- lab/demo-a14/falsifiers.json - F-A14al..am retargeted; F-A14an..av added

Tests run:
- python3 -B -I -m unittest discover -s lab/demo-a14/tests -v -> Ran 76 tests ... OK
- git diff --check -> clean
- planted every entry in lab/demo-a14/falsifiers.json -> 48 CAUGHT of 48, then suite OK
- sh lab/demo-a14/falsify.sh -> falsifier: CAUGHT (ssh-keygen PATH plant)

Not run here: real Mac A14, native arm64, Rosetta, sandbox-exec, xattr quarantine, xcode-select.

Falsifiers: 48/48 CAUGHT (39 before this round, 9 new: F-A14an..av; F-A14al, F-A14aj, F-A14am, F-A14ai retargeted).

Guest hash: unchanged (no wasm guest edit)
Import list: unchanged
Principles: 6 existing trees keep their git commands; 11 fail closed then explain; 12 docs, code, tests agree
DeepSeek: none
Not proven: A14 PASS on Sash's Mac
Checklist: unchanged
Questions: none

## Linux fresh-clone dry run (A14 NOT RUN)

Clone `/tmp/a14-run-20261026-215209` at f721ec79. Workspace `/workspace` stayed on this branch at the same HEAD.

- Dest that already exists: refused.
- Step 1: `git clone --branch` created a new folder; `install.sh` present; porcelain empty. Existing workspace unchanged.
- Step 2: `preflight: FAIL` in 0s (Linux, x86_64, no pinned linux toolchain dir at that moment, no sandbox-exec, no lsof).
- Step 3 with `CARGO_TARGET_DIR=../elsewhere`: exit 3, `REFUSED: this machine is not ready.`, named `CARGO_TARGET_DIR=../elsewhere` plus the same preflight gaps. No signing key. No `current/`. Wrote `this-run` and `summary.txt`.
- Step 3 without that variable: exit 3, same full preflight list, no key, new summary.
- Step 4: exit 3, demo not installed, new `summary.txt`, `this-run` points at that folder.
- Step 5 as written (Library path): `open` not invoked.
- Step 5 using isolated `this-run`: would open only that run's `summary.txt`.
