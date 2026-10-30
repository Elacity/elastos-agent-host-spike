# Independent adversarial review r2: PR #416 A2 Mac runbook

```text
PR:        #416 A2: one-paste Mac runbook
Head:      fc80dd8e9cb22f66b4146f2aeb3b281eca54da51
Range:     git diff 9e7a85d6..HEAD  (three new files under lab/a2-mac-runbook/)
Reviewer:  Cursor Grok (Grok family; author of #416 is Claude)
Prior:     #424 at 21a07f589707e51400566a336e7675f32ff46bad, verdict GO-with-patch
Verdict:   GO-with-patch
Date:      27 Oct 2026
```

A2 on a Mac stays **NOT RUN** until Sash's own `summary.txt` ends with
`A2: PASS.` Do not book from this Linux review. Do not book from the
unpatched fence on a Mac: this head can still print `A2: PASS.` after
`run.sh` starts a `setsid` / `os.setsid()` daemon that rewrites
`evidence.txt` later, or when `evidence.txt` is a symlink outside the
temp clone.

Do not merge #416. This review did not push to
`cursor/a2-mac-runbook-f873`.

## What was reviewed

Detached checkout of
`fc80dd8e9cb22f66b4146f2aeb3b281eca54da51`. Range is only
`9e7a85d6..HEAD`:

| File | Role |
| --- | --- |
| `lab/a2-mac-runbook/RUNBOOK.md` | One ` ```bash ` paste fence |
| `lab/a2-mac-runbook/README.md` | Fence sha/bytes and dry-run table |
| `lab/a2-mac-runbook/dryrun.py` | Linux recorder of that fence |

No 0.8.0 runtime file, no `lab/a2-e2e-resume/` edit, no committed
`guest.sha256` change. `lab/a2-e2e-resume/guest.sha256` is still the
Linux pin `0e868fc1b7565f317c06b514992c90e1d75bdeeb1c0e92d2172e4dd4d41cbace`
at both `9e7a85d6` and this head.

## Paste sha

The only ` ```bash ` fence in `RUNBOOK.md`, body including the
trailing newline, not the markdown fences. Extracted the same way
Sash copies the GitHub / rendered block (text between the fences):

```text
sha256 cd41affbdad608214d824f9082aef78958e134e5b813d7adf1980a44f55b9a4e
bytes  15459
```

Matches README and the #416 PR body. A copy that drops the trailing
newline is a different hash
(`b3d21a0ceabab6f8f3e025678b91eb9a9845238bdee4d2dd6a4d578a3c34e6e1`,
15458 bytes). Paste the fence body with that last newline.

The fence has no `sudo`, no `curl|sh`, no `elastos serve`, no
`sed -i`, no `readlink -f`, and no GNU `stat -c`. The word `curls`
appears only in the comment "The paste never curls rustup.rs". Hash
uses `sha256sum --` or `shasum -a 256 --`. Paths use `pwd -P` and
`python3 -I` `realpath` for the pin write.

## Dry-run, rerun here

This host had no `zsh`. Installed `zsh 5.9` (Ubuntu) so the author's
recorder could run. Then, from `fc80dd8e`:

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

```text
BLOCK sha256:cd41affbdad608214d824f9082aef78958e134e5b813d7adf1980a44f55b9a4e bytes:15459
README meta CAUGHT
static sudo CAUGHT
static elastos-serve CAUGHT
static rustup-skip CAUGHT
static mktemp-trap CAUGHT
static no-single-branch CAUGHT
happy: last='A2: PASS.' exit=0 CAUGHT
planted-fail: last='A2: FAIL.' exit=1 CAUGHT
missing-tool: last='A2: NOT RUN.' exit=2 CAUGHT
tampered-hash: last='A2: FAIL.' exit=1 CAUGHT
missing-row: last='A2: NOT RUN.' exit=2 CAUGHT
duplicate-write: last='A2: FAIL.' exit=1 CAUGHT
survived-line: last='A2: FAIL.' exit=1 CAUGHT
late-rewrite: last='A2: FAIL.' exit=1 CAUGHT
missing-pin: last='A2: NOT RUN.' exit=2 CAUGHT
elastos-created: last='A2: FAIL.' exit=1 CAUGHT
runsh-exit1: last='A2: FAIL.' exit=1 CAUGHT
pass-then-fail: last='A2: FAIL.' exit=1 CAUGHT
DRYRUN: PASS
A2 booking: NOT RUN ON MAC
```

The five #424 survivors are closed on this head:

| #424 plant | Then | Now |
| --- | --- | --- |
| duplicate `WRITE: PASS` | `A2: PASS.` SURVIVED | `A2: FAIL.` CAUGHT |
| `SURVIVED` line and exit 0 | `A2: PASS.` SURVIVED | `A2: FAIL.` CAUGHT |
| background 8s rewrite (same process group) | `A2: PASS.` SURVIVED | `A2: FAIL.` CAUGHT |
| clone has no `9e7a85d6` object | `A2: PASS.` SURVIVED | `A2: NOT RUN.` CAUGHT |
| `run.sh` exit 1 with all-PASS evidence | `A2: PASS.` SURVIVED | `A2: FAIL.` CAUGHT |

## Reviewer plants (new; not in dryrun.py)

Each plant is a stub remote plus the exact fence under `zsh --no-rcs`
5.9 with the Darwin `uname` / `xcode-select` shim. Real
`/home/ubuntu/.elastos` stayed absent. These are not the author's
twelve cases.

| # | Plant | Want | Last line | Result |
| --- | --- | --- | --- | --- |
| 1 | `run.sh` writes PASS evidence, `setsid` daemon sleeps 12s, rewrites FAIL | no `A2: PASS.` | `A2: PASS.` then evidence becomes FAIL | **SURVIVED** |
| 1b | same rewrite via `nohup` (stays in the process group) | `A2: FAIL.` | `A2: FAIL.` (`STALE`) | **CAUGHT** |
| 1c | Python `os.setsid()` + double-fork (macOS shape; no `setsid` binary) | no `A2: PASS.` | `A2: PASS.` then evidence becomes FAIL | **SURVIVED** |
| 2 | `evidence.txt` is a symlink to `$HOME/planted-evidence.txt` | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 3a | row name `WRITE : PASS` (space before colon) | no `A2: PASS.` | `A2: NOT RUN.` (`missing rows WRITE`) | **CAUGHT** |
| 3b | `WRITE: FAIL\\rWRITE: PASS` on one physical line | no `A2: PASS.` | `A2: FAIL.` (disagreeing rows) | **CAUGHT** |
| 3c | lookalike `WRΙTE: FAIL` (Greek iota) plus a real `WRITE: PASS` | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** (weak) |
| 4 | `run.sh` writes `A2: PASS.` into `summary.txt`; evidence is FAIL | `A2: FAIL.` | `A2: FAIL.` (summary overwritten) | **CAUGHT** |
| 5 | `A2_SUMMARY` already holds an old `A2: PASS.` | `A2: FAIL.` | `A2: FAIL.` (summary overwritten) | **CAUGHT** |
| 6 | `HOME` is a dummy; `run.sh` creates a different home's `~/.elastos` | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 6b | `~/.elastos` already exists; `run.sh` writes a file into it | no `A2: PASS.` | `A2: PASS.` | **SURVIVED** |
| 7a | `A2_REMOTE` is a depth-1 clone of a real pin descendant | pin check still honest | `A2: PASS.` (pin object present, ancestor true) | not a lie |
| 7b | remote uses `git replace --graft` to fake the pin parent | no `A2: PASS.` | `A2: NOT RUN.` (replace refs do not clone) | **CAUGHT** |
| 7c | remote has the pin object plus a lying `.git/shallow` line | no `A2: PASS.` | `A2: NOT RUN.` (`is-ancestor` stays false) | **CAUGHT** |
| 8a | same fence under zsh and bash, happy path | both `A2: PASS.` | both `A2: PASS.` exit 0 | **CAUGHT** |
| 8b | `sha256sum` absent; `shasum -a 256` only (isolated `a2_hash_file`) | same digest | digest matched | **CAUGHT** |
| 8c | `set -euo pipefail; false \| true` in zsh and bash | both abort | both rc 1, no later word | **CAUGHT** |

Plant 1 took 2.9s to print `A2: PASS.`. Twelve seconds later
`evidence.txt` was the FAIL fixture. Plant 1c did the same with
tools that exist on Sash's Mac (`python3` + `os.setsid()`). Plant 1b
shows the author's process-group waiter does catch `nohup` without
`setsid`.

Plant 2 booked PASS while `evidence.txt` resolved under the dummy
`$HOME`, outside the temp clone. The pin write already uses
`realpath`. Evidence does not.

Plant 3c is noise: the scored `WRITE` row is a real PASS. A human
reading `evidence.txt` can see a lookalike FAIL line. Same class as
the #424 optional duplicate-PASS note.

Plant 6 is the case the paste documents: `HOME` stays the login home
so rustup works, and the check is `$HOME/.elastos`. When the caller
points `HOME` at a dummy, that check watches the dummy. Plant 6b is
the #424 leftover: creation is refused, a write into an existing
tree is not. On Sash's Mac `~/.elastos` is likely already there. The
real A2 driver stores under `lab/a2-e2e-resume/homes/` inside the
clone, so 6b is residual unless a lying `run.sh` writes through
`HOME`.

Plant 7a is a real descendant cloned through a shallow remote. The
paste fetched the pin and `merge-base --is-ancestor` was true. That
is the intended PASS. Plants 7b and 7c are the fake-ancestor cases
and both stay NOT RUN.

Plant 8b on the full fence needs `sha256sum` *absent*, not a broken
shim on `PATH`. A shim named `sha256sum` that exits 127 makes
`command -v` succeed, `set -e` stops the paste, and the EXIT trap
writes `A2: NOT RUN.` The Mac path is: no `sha256sum`, use
`shasum`. The isolated function produced the same digest as
`hashlib.sha256`. The Darwin `ps` waiter branch is unused on this
Linux host because `/proc` exists; `ps -ax -o pid= -o pgid=` is the
usual BSD form.

## Findings that need a patch

### F1. `A2: PASS.` while a `setsid` child still rewrites evidence

The waiter forks `run.sh` into its own process group and waits until
that group is empty. `setsid` / `os.setsid()` leaves the group. The
snapshot, the hash recheck, and `a2_finish` then run. A 12s sleep is
enough to book PASS and rewrite afterwards.

The author's late-rewrite plant stays in the group, so dryrun stays
green. A lying `run.sh` on any descendant of `9e7a85d6` can still
book A2. The real `lab/a2-e2e-resume/run.sh` is synchronous; this
hole is the lying-`run.sh` case that #424 already treated as
required.

### F2. `evidence.txt` may live outside the temp clone

`cp --` follows a symlink and hashes the target. A PASS file outside
the workdir books A2. The pin path already refuses a `realpath`
outside the workdir. Evidence needs the same rule, plus "regular
file, not a symlink".

### F3. `$HOME/.elastos` is the only home that is watched (weaker)

The paste never changes `HOME`. A wrapper that does, or a `run.sh`
that writes the login home while `HOME` is a dummy, bypasses the
check. A write into a pre-existing `~/.elastos` still books PASS
(plant 6b; same leftover as #424).

## Exact patch

Apply in the ` ```bash ` fence in `lab/a2-mac-runbook/RUNBOOK.md`,
then recompute the fence sha256 and bytes and update README. A copy
of this patch was replayed here against plants 1 and 2: both became
`A2: FAIL.`, and the happy path stayed `A2: PASS.`

**1. Wait for processes that still name the A2 lane, not only the
process group.** In the `A2WAIT` Python, after `alive()`:

```python
def argv_mentions(needle):
    found = []
    try:
        out = subprocess.check_output(
            ["ps", "-ax", "-o", "pid=", "-o", "command="], text=True
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    self_pid = os.getpid()
    for line in out.splitlines():
        if needle not in line:
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == self_pid:
            continue
        found.append(pid)
    return found


lane = os.path.abspath("lab/a2-e2e-resume")
```

In the wait loop, treat the group as busy while `argv_mentions(lane)`
is non-empty (same `empty >= 2` settle). If `ps` cannot run, exit 1.
`ps -ax -o pid= -o command=` is the BSD form. A daemon that drops
the lane from its argv can still sneak; that is residual.

**2. Refuse evidence that is not a regular file inside the clone.**
Immediately after `a2_evidence=...` and before the snapshot `cp`:

```bash
if [ -e "$a2_evidence" ]; then
  if [ -L "$a2_evidence" ] || [ ! -f "$a2_evidence" ]; then
    a2_finish "FAIL" "evidence.txt is not a regular file in the clone"
  fi
  if ! python3 -I -c '
import os, sys
ev = os.path.realpath(sys.argv[1])
root = os.path.realpath(sys.argv[2])
raise SystemExit(0 if ev.startswith(root + os.sep) else 1)
' "$a2_evidence" "$a2_clone"; then
    a2_finish "FAIL" "evidence.txt resolves outside the temp clone"
  fi
fi
```

**3. Watch the login home as well as `$HOME` (optional, plant 6).**
Before the rustup skip:

```bash
a2_login_home=$(python3 -I -c 'import pwd, os; print(pwd.getpwuid(os.getuid()).pw_dir)')
if [ -e "$HOME/.elastos" ] || [ -e "$a2_login_home/.elastos" ]; then
  a2_elastos_before=PRESENT
else
  a2_elastos_before=ABSENT
fi
```

After the journey, refuse creation of either path. A write into an
already-present `~/.elastos` stays residual (plant 6b), as in #424.

Add dry-run cases for a `setsid` rewrite and a symlinked
`evidence.txt`. Recompute the fence sha/bytes. Then Sash pastes on
Apple Silicon.

## What can stay

- The five #424 survivors are closed.
- Trailing-space row names cannot book PASS.
- A CR that splits FAIL and PASS on one line is FAIL.
- `run.sh` cannot keep an old or self-written `A2: PASS.` in
  `summary.txt` when the scorer writes FAIL.
- A grafted or shallow-fake pin does not become a descendant.
- zsh and bash agree on `set -euo pipefail` and on the happy path.
- `shasum -a 256` matches `sha256sum` when `sha256sum` is absent.
- No `sudo`, no `curl|sh`, no `elastos serve`, no `sed -i`, no
  `readlink -f`, no GNU `stat`.
- Pin write stays inside the temp clone. This range does not commit
  a Mac guest hash.
- Default paste does not `rm -rf` the workdir.

## Principles

- 11 Fail closed: a `setsid` rewrite and an evidence symlink still
  book PASS (F1, F2).
- 12 Docs, code, tests agree: README says the late-rewrite plant is
  CAUGHT; that plant never leaves the process group.
- 3 No ambient authority: `XDG_*` is the temp folder; evidence and a
  redirected `HOME` can still write outside it.
- 6 Operator vs user: this is a lab paste, not Home.

## A2 booking

**NOT RUN ON MAC.**

Do not treat any Linux `A2: PASS.` as a booking. Do not treat a Mac
`summary.txt` from this unpatched fence as a booking if `run.sh`
could still be rewriting evidence. After the patch, book A2 only
when Sash's Mac `summary.txt` ends with `A2: PASS.`
