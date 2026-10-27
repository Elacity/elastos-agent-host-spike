# Independent adversarial review: PR #416 A2 Mac runbook

```text
PR:        #416 A2: one-paste Mac runbook
Head:      21a07f589707e51400566a336e7675f32ff46bad
Range:     git diff 9e7a85d6..HEAD  (three new files under lab/a2-mac-runbook/)
Reviewer:  Cursor Grok (Grok family; author of #416 is Claude)
Verdict:   GO-with-patch
Date:      27 Oct 2026
```

A2 on a Mac stays **NOT RUN** until Sash's own `summary.txt` ends with
`A2: PASS.` Do not book from this Linux review, and do not book from
the unpatched paste on a Mac: this head can print `A2: PASS.` while
`run.sh` failed or the clone is not the A2 pin.

Do not merge #416. This review did not push to `cursor/a2-mac-runbook-f873`.

## What was reviewed

Detached worktree at `/tmp/review-a2-416` on
`21a07f589707e51400566a336e7675f32ff46bad`. Range is only
`9e7a85d6..HEAD`:

| File | Role |
| --- | --- |
| `lab/a2-mac-runbook/RUNBOOK.md` | One ` ```bash ` paste fence |
| `lab/a2-mac-runbook/README.md` | Fence sha/bytes and dry-run table |
| `lab/a2-mac-runbook/dryrun.py` | Linux recorder of that fence |

No 0.8.0 runtime file, no `lab/a2-e2e-resume/` edit, no committed
`guest.sha256` change.

## Paste sha

The only ` ```bash ` fence in `RUNBOOK.md`, body including the
trailing newline, not the markdown fences:

```text
sha256 409684d41a3c97f476085a05e61fca5c571583c8e41f86a8147013f4bf9d41eb
bytes  11683
```

Matches README and the PR body. Recomputed here with Python
`hashlib.sha256` on the extracted fence.

## Dry-run, rerun here

This host had no `zsh`. Installed `zsh 5.9` (Ubuntu) so the author's
recorder could run. Then, from the detached worktree:

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

```text
BLOCK sha256:409684d41a3c97f476085a05e61fca5c571583c8e41f86a8147013f4bf9d41eb bytes:11683
README meta CAUGHT
static sudo CAUGHT
static elastos-serve CAUGHT
static rustup-skip CAUGHT
static mktemp-trap CAUGHT
happy: last='A2: PASS.' exit=0 CAUGHT
planted-fail: last='A2: FAIL.' exit=1 CAUGHT
missing-tool: last='A2: NOT RUN.' exit=2 CAUGHT
tampered-hash: last='A2: FAIL.' exit=1 CAUGHT
DRYRUN: PASS
A2 booking: NOT RUN ON MAC
```

Same four cases as README. Without the Darwin shim the same fence
ends `A2: NOT RUN.` with `operating system is Linux` and
`architecture is x86_64`. CAUGHT.

## Mac / zsh hunt

The paste is meant for interactive zsh on Apple Silicon. This review
ran it under `zsh --no-rcs` 5.9 with a `uname` / `xcode-select` shim,
same as `dryrun.py`. It is not a real Mac.

| Check | Result |
| --- | --- |
| `set -euo pipefail` | zsh 5.9 accepts it; `pipefail` is on |
| `[[`, `local`, `function`, `<(`, `&>`, `echo -e` | none as shell syntax (`local` appears only in the words "local changes") |
| `sed -i`, `readlink -f`, `stat` | unused |
| `date -u +%Y-%m-%dT%H:%M:%SZ` | POSIX; works on BSD date |
| `df -Pk` | POSIX one-line form; avoids BSD `df` wrap |
| `mktemp -d "${TMPDIR:-/tmp}/a2-mac-runbook.XXXXXX"` | Xs are the last component; BSD and GNU both accept this |
| `sha256sum --` / `shasum -a 256 --` | fallback is present; Mac without coreutils uses `shasum` |
| `pwd -P` | used instead of `readlink -f` |
| pin write | `python3 -I` `realpath` refuses a pin outside the temp workdir |
| `sudo`, `curl`, `elastos serve` | absent from the fence (the words `rustup.rs` and `xcode-select --install` are comment / missing-tool text only) |
| `rm -rf` | only `a2_cleanup`, and only when `A2_CLEAN=1`; default paste keeps the temp folder |
| `git add` / `commit` / `push` | absent; staged-file check after the pin write |
| guest pin in the #416 range | `lab/a2-e2e-resume/guest.sha256` is still the Linux pin `0e868fc1…41cbace`; the range does not touch it |
| `set -e` + EXIT trap | `a2_finish` sets `a2_finished=1` before `exit`; INT/TERM go through EXIT and write `A2: NOT RUN.` if no verdict yet |
| `a2_journey_rc` | printed, then ignored (see plants) |
| ancestor pin | skipped when `git cat-file` cannot see `9e7a85d6` (see plants) |

`CARGO_TARGET_DIR` set is a named NOT RUN. Spaces in the workdir are
a named NOT RUN. Workdir under `~/.elastos` is a named NOT RUN, but
only after `mkdir -p` if `A2_WORKDIR` pointed there and did not yet
exist.

Default `A2_CLEAN` is off, so the paste does not delete the temp
folder or anything outside it. Cargo and rustup still write their
usual caches under `HOME` / `RUSTUP_HOME` / `CARGO_HOME`. That is
documented for rustup. The paste never runs `sudo`.

## Reviewer plants (new; not in dryrun.py)

Each plant is a stub remote plus the exact fence under zsh. Real
`~/.elastos` stayed absent on this host (`HOME=/home/ubuntu`). The
`elastos-created` plant used a fake `HOME` and kept the real rustup
root via `RUSTUP_HOME`.

| # | Plant | Want | Last line | Result |
| --- | --- | --- | --- | --- |
| 1 | `WRITE2` row missing; `A2_counted: yes` | no `A2: PASS.` | `A2: NOT RUN.` (`missing rows WRITE2`) | **CAUGHT** |
| 2 | Duplicate `WRITE: PASS` line | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 3 | `run.sh` prints `F-REV-GUEST-HASH SURVIVED` and exits 0; six PASS rows | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 4 | `run.sh` writes PASS evidence, backgrounds an 8s rewrite to FAIL, exits 0 | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 5 | Clone has the lab files but no `9e7a85d6` object | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 6 | `run.sh` creates `$HOME/.elastos` (fake HOME) | `A2: FAIL.` | `A2: FAIL.` (`this run created …/.elastos`) | **CAUGHT** |
| 7 | `run.sh` exits 1 after all-PASS `evidence.txt` (falsifier failed) | no `A2: PASS.` | `A2: PASS.` (`JOURNEY run.sh -> 1`) | **SURVIVED** |
| 8 | Same row `PASS` then `FAIL` | `A2: FAIL.` | `A2: FAIL.` (`evidence has disagreeing rows`) | **CAUGHT** |

Extra hunt, not in the six asked plants: if `~/.elastos` already
exists, a write into it still ends `A2: PASS.` **SURVIVED**. The
paste only refuses creation. On Sash's Mac that directory is likely
already there. The A2 driver itself stores under
`lab/a2-e2e-resume/homes/` inside the clone, so this is residual
unless some other step writes through `HOME`.

## Findings that need a patch

### F1. `A2: PASS.` while `run.sh` failed (booking lie)

`lab/a2-e2e-resume/run.sh` writes `evidence.txt` from the harness,
then runs `falsify.py`. A2 is counted only when every row is computed
PASS **and** every falsifier is CAUGHT. The paste scores only
`evidence.txt`. It prints `JOURNEY run.sh -> N` and then ignores `N`.

Plant 7 is the real Mac case: harness PASS, a falsifier survives,
`run.sh` exits 1, summary still ends `A2: PASS.`

Plant 3 is the lying-`run.sh` case: exit 0 plus a SURVIVED line,
same `A2: PASS.`

### F2. Wrong clone is booked

After `git clone --single-branch`, either `9e7a85d6` is reachable
from HEAD (so it is an ancestor) or it is not in the object database.
The fence does:

```bash
if git cat-file -e "${a2_pin_a2}^{commit}" 2>/dev/null; then
  if ! git merge-base --is-ancestor "$a2_pin_a2" HEAD; then
    a2_finish "NOT RUN" "clone is not a descendant of A2 head ${a2_pin_a2}"
  fi
fi
```

A missing pin commit skips the check. The author's own happy-path
fixture is that case, and it books `A2: PASS.` Plant 5 did the same.

The intended GitHub clone of `cursor/a2-mac-runbook-f873` does
contain `9e7a85d6` as the parent, so a default Sash paste hits the
ancestor path. A wrong `A2_REMOTE` / `A2_BRANCH` that still has the
four lab files does not.

### F3. Duplicate PASS row (weaker)

The scorer treats a second `WRITE: PASS` as the same result, so no
conflict. It cannot book a missing row (plant 1) and it does refuse
PASS-then-FAIL (plant 8). Duplicate PASS is noise, not a failed row
hiding as PASS. Optional.

## Exact patch

Apply in the ` ```bash ` fence in `lab/a2-mac-runbook/RUNBOOK.md`,
then recompute the fence sha256 and bytes and update README.

**1. Fail closed when the A2 pin is missing or not an ancestor**
(replace the `git cat-file` / `merge-base` block):

```bash
if ! git cat-file -e "${a2_pin_a2}^{commit}" 2>/dev/null \
  || ! git merge-base --is-ancestor "$a2_pin_a2" HEAD; then
  a2_finish "NOT RUN" "clone is not a descendant of A2 head ${a2_pin_a2}"
fi
```

`dryrun.py` happy-path fixture must then make the stub commit a
descendant of `9e7a85d631aec12de8c1da4fc4958bce18252d21` (fetch that
object from this repo, then commit the stub on top). Add a fifth
dry-run case: stub with no pin object expects `A2: NOT RUN.`

**2. Do not book PASS when `run.sh` is nonzero**
(after the scorer sets `a2_verdict`, before the `~/.elastos` check):

```bash
if [ "$a2_verdict" = PASS ] && [ "${a2_journey_rc:-1}" -ne 0 ]; then
  a2_finish "FAIL" "run.sh exited ${a2_journey_rc}; A2 cannot PASS while the journey or its falsifiers failed"
fi
```

Add a dry-run case: all-PASS `evidence.txt` and `run.sh` exit 1
expects `A2: FAIL.`

Optional, same scorer: treat a second line for a name as `conflict`
even when both say PASS. Optional: after `run.sh`, refuse PASS if
any child of that process is still running (plant 4). Neither blocks
a real `run.sh`, which is synchronous.

After the patch, paste the new fence into zsh on this Linux host with
the shim and rerun `dryrun.py` plus plants 1, 3, 5, and 7. Then Sash
pastes on Apple Silicon.

## What can stay

- Missing row cannot become `A2: PASS.`
- Tampered guest hash after the pin write is FAIL.
- Missing `rustup` (and the rustup bin-dir siblings) is NOT RUN.
- Creating `~/.elastos` when it was absent is FAIL.
- Disagreeing duplicate rows are FAIL.
- No `sudo`, no `curl`, no `elastos serve`, no `xcode-select --install`.
- Pin write is confined to the temp clone; this range does not commit
  a Mac guest hash.
- Default paste does not `rm -rf` the workdir.
- BSD-safe `mktemp` / `df -Pk` / `date` / `shasum` fallback / no
  `sed -i` / no `readlink -f`.

## Principles

- 11 Fail closed: a missing journey row is NOT RUN; a failed
  falsifier and a missing A2 pin are not (F1, F2).
- 12 Docs, code, tests agree: README says book only on computed PASS
  rows; `lab/a2-e2e-resume/README.md` also requires every falsifier
  CAUGHT. The paste implements only the first half.
- 3 No ambient authority: `XDG_*` is the temp folder; `HOME` stays
  the login home so rustup works; creation of `~/.elastos` is refused.
- 6 Operator vs user: this is a lab paste, not Home.

## A2 booking

**NOT RUN ON MAC.**

Do not treat any Linux `A2: PASS.` as a booking. Do not treat a Mac
`summary.txt` from this unpatched fence as a booking if `run.sh`
printed a nonzero journey line. After the patch, book A2 only when
Sash's Mac `summary.txt` ends with `A2: PASS.`
