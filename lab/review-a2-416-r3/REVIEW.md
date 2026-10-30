# Independent adversarial review r3: PR #416 A2 Mac runbook

```text
PR:        #416 A2: one-paste Mac runbook
Head:      a1971a3cdd3cd20145174bad8ada9c753af3456b
Range:     git diff 9e7a85d6..HEAD  (three new files under lab/a2-mac-runbook/)
Reviewer:  Cursor Grok (Grok family; author of #416 is Claude)
Prior:     #434 r2 at fc80dd8e, verdict GO-with-patch; this head applies that patch
Verdict:   GO-with-patch
Date:      27 Oct 2026
```

A2 on a Mac stays **NOT RUN** until Sash's own `summary.txt` ends with
`A2: PASS.` Do not book from this Linux review. Do not hand him the
unpatched fence: this head can still print `A2: PASS.` after a
`setsid` / `exec -a mds` helper that lives outside the temp dir sleeps
past the 15s quiet period and then rewrites `evidence.txt`, and it can
false-FAIL or hang on a real Mac when Spotlight holds a file in
`lab/a2-e2e-resume` or another process's argv contains that string.

Do not merge #416. This review did not push to
`cursor/a2-mac-runbook-f873`.

## What was reviewed

Detached checkout of
`a1971a3cdd3cd20145174bad8ada9c753af3456b`. Range is only
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
sha256 d19219ff8b076f12aed711ca048130219c2b5e4b0646559eeb4f10569361d517
bytes  22309
```

Matches README and the #416 PR body.

The fence has no `sudo`, no `curl|sh`, no `elastos serve`, no
`sed -i`, no `readlink -f`, and no GNU `stat -c`. The word `curls`
appears only in the comment "The paste never curls rustup.rs".
`rm -rf` appears once, and only as `rm -rf -- "$a2_workdir"` when
`A2_CLEAN=1` (the default paste leaves the temp folder). The pin
write uses `python3 -I` `realpath` and refuses a path outside the
temp workdir. Hash uses `sha256sum --` or `shasum -a 256 --`.

It does not write `$HOME/.elastos`. It snapshots that tree (and the
login-home `~/.elastos`) and FAILs if the run creates or changes it.
`HOME` stays the login home so rustup can write `~/.rustup`; `XDG_*`
points at the temp folder.

## Dry-run, rerun here

This host had no `zsh`. Installed `zsh 5.9` (Ubuntu) so the author's
recorder could run. Then, from `a1971a3c`:

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

```text
BLOCK sha256:d19219ff8b076f12aed711ca048130219c2b5e4b0646559eeb4f10569361d517 bytes:22309
README meta CAUGHT
static sudo CAUGHT
static elastos-serve CAUGHT
static rustup-skip CAUGHT
static mktemp-trap CAUGHT
static no-single-branch CAUGHT
static bsd-portable CAUGHT
static no-curl-sh CAUGHT
static argv-wait CAUGHT
static lsof-quiet CAUGHT
static login-home CAUGHT
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
setsid-rewrite: last='A2: FAIL.' exit=1 CAUGHT
python-double-fork: last='A2: FAIL.' exit=1 CAUGHT
evidence-symlink: last='A2: FAIL.' exit=1 CAUGHT
lookalike-row: last='A2: FAIL.' exit=1 CAUGHT
home-redirect: last='A2: FAIL.' exit=1 CAUGHT
existing-elastos-write: last='A2: FAIL.' exit=1 CAUGHT
DRYRUN: PASS
A2 booking: NOT RUN ON MAC
```

All 18 author cases CAUGHT. The six r2 plants that this head added
to `dryrun.py` stay closed.

## Reviewer plants (new; not in dryrun.py)

Recorder: `lab/review-a2-416-r3/plants.py`. Each plant is a stub
remote plus the exact fence under `zsh --no-rcs` 5.9 with the Darwin
`uname` / `xcode-select` shim. Real `/home/ubuntu/.elastos` stayed
absent.

CAUGHT here means the fence did not book a false `A2: PASS.` (or,
for the Mac false-FAIL plants, that it did not fail an honest
happy path). SURVIVED means the hole is still open.

| # | Plant | Want | Last line | Result |
| --- | --- | --- | --- | --- |
| 1 | `os.setsid` + `exec -a mds`; helper lives under `/tmp`; sleeps 22s; then writes FAIL | no `A2: PASS.` | `A2: PASS.` then evidence FAIL | **SURVIVED** |
| 1b | same via `nohup` + `setsid` + `exec -a mds`, delay 22s | no `A2: PASS.` | `A2: PASS.` then evidence FAIL | **SURVIVED** |
| 1c | inherited write fd held open during `lsof` (setsid, 8s) | `A2: FAIL.` | `A2: FAIL.` (live writer) | **CAUGHT** |
| 1d | inherited fd closed; reopen the path after 22s | no `A2: PASS.` | `A2: PASS.` then FAIL | **SURVIVED** |
| 1e | `at` / `launchd` / `cron` | no `A2: PASS.` | no `at`/`launchctl` here; same hole as 1 | **SURVIVED** |
| 2a | hard link of `evidence.txt`; rewrite via the other name at 8s | `A2: FAIL.` | `A2: FAIL.` (quiet-period hash moved) | **CAUGHT** |
| 2b | hard link; rewrite via the other name at 22s | no `A2: PASS.` | `A2: PASS.` then FAIL | **SURVIVED** |
| 3 | watcher writes live `evidence.txt` when `evidence.snap` appears | `A2: FAIL.` | `A2: FAIL.` (changed after snapshot) | **CAUGHT** |
| 4 | FAIL journey; detached helper rewrites `summary.txt` to `A2: PASS.` after score | file stays FAIL | file ended `A2: PASS.` | **SURVIVED** |
| 5a | zero-width space in a row name plus real PASS rows | no `A2: PASS.` | `A2: FAIL.` (non-ASCII row name) | **CAUGHT** |
| 5b | fullwidth `ＷＲＩＴＥ: FAIL` plus real PASS rows | no `A2: PASS.` | `A2: FAIL.` (non-ASCII row name) | **CAUGHT** |
| 5c | trailing spaces after `WRITE: PASS` | `A2: PASS.` | `A2: PASS.` | **CAUGHT** |
| 5d | `WRITE\x00: PASS` (NUL in the name; isolated scorer) | no false PASS | `A2: NOT RUN.` (missing WRITE) | **CAUGHT** |
| 5e | lowercase `write: FAIL` plus real `WRITE: PASS` | not a scored FAIL | `A2: PASS.` (lowercase is not a row) | **CAUGHT** |
| 6 | HEAD is a descendant of the parent of `9e7a85d6`, not of the pin | `A2: NOT RUN.` | `A2: NOT RUN.` | **CAUGHT** |
| 7 | same-size overwrite of a pre-existing `~/.elastos` file; `os.utime` restores ns | no `A2: PASS.` | `A2: PASS.` (`plante\n` vs `before\n`) | **SURVIVED** |
| 8 | `HOME` dummy; `run.sh` creates the login-home `~/.elastos` (r2 replay) | `A2: FAIL.` | `A2: FAIL.` | **CAUGHT** |
| 9 | read-only fd on `harness.py` (`exec -a mds`, 20s) | still `A2: PASS.` | `A2: FAIL.` (lsof treats a reader as a writer) | **SURVIVED** (false FAIL) |
| 10 | unrelated process whose argv contains `lab/a2-e2e-resume` | still `A2: PASS.` | waiter hung past 25s | **SURVIVED** (false hang) |
| 11 | happy evidence with an em-dash in the detail | `A2: PASS.` | `A2: PASS.` | **CAUGHT** |
| 12a | `bash -n` and `zsh -n` on the fence; no bash 4-only flags | both clean | both rc 0; no hits | **CAUGHT** |
| 12b | happy path under `bash --noprofile --norc` | `A2: PASS.` | `A2: PASS.` (bash 5.2; no 3.2 on this host) | **CAUGHT** |
| 12c | BSD-portable flags | no GNU-only `sed`/`stat`/`readlink` | absent | **CAUGHT** |

Plant 1 printed `A2: PASS.` in 25.9s. Eight seconds of linger later
`evidence.txt` was the FAIL fixture. The helper's argv was
`mds -I /tmp/r3-a2-plant-…/rewriter.py`, so the process-group wait,
the `ps` path needle, and `lsof` (file not yet open) all missed it.
The 15s quiet period is a finite window. A 22s sleep walks past it.
`nohup` does not change that. `launchd` / `at` / `cron` are the same
shape: no live process and no open fd at check time.

Plant 1c shows `lsof` does catch a write fd that stays open. Plant
1d closes that fd and opens the path later; it books PASS.

Plant 2a is the r2 quiet-period backstop: a hard link is still a
regular file inside the clone (`realpath` stays put), but an 8s
write through the other name moves the hash. Plant 2b waits 22s and
books PASS.

Plant 3 is the TOCTOU between `cp` and the post-score re-hash. The
current post-score check FAILs if live bytes move after the snap.
That window is closed. A write *after* `a2_finish` is plant 1.

Plant 4 is booking by file. The paste's stdout still said
`A2: FAIL.`. The helper rewrote `summary.txt` after `a2_finish`.
Sash is told to book from that file.

Plant 5d: the in-harness `nul-row` script failed to write
`evidence.txt` (FAIL, not a false PASS). The isolated scorer, given
a NUL in the `WRITE` name, returns `NOT RUN` / missing WRITE. A NUL
*after* `PASS` still scores PASS (`startswith`); that is the same
class as junk after a real PASS, not a hidden FAIL row. Extra
`WRITE\x00: FAIL` next to a real `WRITE: PASS` is ignored (NUL is
not `ord > 127`).

Plant 7 is the leftover `~/.elastos` snapshot: kind, mtime_ns, size,
relative path. Same bytes length and restored nanoseconds book PASS
while the file contents changed.

Plant 9 is a false FAIL on a real Mac. `lsof +D` on
`lab/a2-e2e-resume` treats any open file as a writer, including a
read-only Spotlight / `mds` fd on `harness.py`. After a guest build
that directory also holds `target/`. Plant 10 is worse: the waiter
also matches the bare substring `lab/a2-e2e-resume` in *any*
process argv, then waits up to 7200s and FAILs. A Cursor window, a
`rg`, or a leftover helper with that string hangs the paste.

Plant 11 and the author's happy fixture already use an em-dash after
`PASS`. That does not false-FAIL. `bash -n` / `zsh -n` are clean.
This host has bash 5.2, not 3.2; the fence uses no bash-4-only
forms. The documented paste target is zsh.

`lsof` missing after the prereq check is fail-closed: the helper
prints `lsof-missing`, which is a non-empty writer list, so the
paste FAILs. A slow `lsof` hangs rather than books PASS.

## Findings that need a patch

### F1. `A2: PASS.` after a delayed writer that evades wait and `lsof`

The waiter, the `ps` needle, and `lsof` only see a process that is
still in the group, still names the temp path, or still has the
file open. A helper that `setsid`s, renames argv (`exec -a mds`),
lives outside the temp dir, and sleeps longer than 15s books PASS
and then rewrites `evidence.txt` or `summary.txt`. Hard links and
`launchd`/`at` are the same hole. The author's 12s plants stay
CAUGHT because they fire during the quiet period.

A finite extra sleep does not close this. Freeze the files.

### F2. `~/.elastos` snapshot ignores file contents

`a2_snapshot_tree` records kind, mtime_ns, size, and relative path.
A same-size overwrite with `os.utime` restored books PASS. On
Sash's Mac `~/.elastos` may already exist.

### F3. False FAIL / hang on a real Mac

`lsof +D` on the whole evidence dir counts readers. The argv waiter
uses the bare string `lab/a2-e2e-resume`. Spotlight, or any other
process that names that folder, can FAIL or hang an honest run.

## Exact patch

Apply in the ` ```bash ` fence in `lab/a2-mac-runbook/RUNBOOK.md`,
then recompute the README sha/bytes. Replay plants 1, 4, 7, 9, and
10 after the edit.

1. **Freeze evidence and summary before the verdict.** After the
   15s quiet re-hash, on Darwin run `chflags uchg` on
   `evidence.txt`, `evidence.snap`, and `summary.txt` (once
   `a2_summary` is known). Re-hash after the freeze. A later writer
   cannot change the booking file. Linux dry-run can skip
   `chflags` when it is absent; the Mac paste has it.

2. **Hash `~/.elastos` file contents.** For each regular file in
   the snapshot, also record `sha256`. Keep mtime/size. Skip
   `.DS_Store`, `._*`, and `.localized` so Finder / Spotlight
   metadata does not false-FAIL a pre-existing tree.

3. **`lsof` only `evidence.txt`, and only write fds.** Drop
   `lsof +D` on the lane. Keep `lsof` on the file. Count a line
   only when the FD column contains `w` or `u`. Ignore COMMAND in
   `mds`, `mdworker`, `mdworker32`, `corespotlightd`, `cloudd`,
   `fseventsd`.

4. **Argv wait: absolute paths only.** In `wait_journey.py`, drop
   the bare needle `lab/a2-e2e-resume`. Keep the absolute workdir
   and the absolute lane. An unrelated Cursor / `rg` argv then
   cannot hang the paste.

Recompute the fence sha/bytes after the edit. Then Sash pastes on
Apple Silicon. Book A2 only on that Mac `summary.txt` ending
`A2: PASS.`

## Principles

- 3 No ambient authority: the paste stays in a temp dir; rustup is
  the documented exception.
- 11 Fail closed, then explain: missing tools and a stale pin stay
  NOT RUN. The 15s quiet period fails open against a later writer.
- 12 Docs, code, tests, and operations must agree: README matches
  the fence sha; A2 stays NOT RUN ON MAC.

## Not proven

- No Apple Silicon paste. BSD `ps` / `lsof` / `chflags` / `dscl`
  were not run on a Mac.
- bash 3.2 is not installed here. Syntax is clean; the paste target
  is zsh.
- `at` / `launchd` are absent on this host. The delay-22 plants are
  the same control flow.

## Next

Patch #416 with the four items above. Do not hand Sash this fence
until that head's r3 plants 1, 4, 7, 9, and 10 are CAUGHT. A2 stays
NOT RUN until his Mac `summary.txt` ends `A2: PASS.`
