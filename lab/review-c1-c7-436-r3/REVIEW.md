# Independent adversarial review r3: PR #436 C1-C7 Mac runbook

```text
PR:        #436 C1-C7: one-paste Mac sandbox-exec runbook
Head:      5f50fc484fcc679c46715340ea5474f9ceec06a9
Range:     git diff ea25c4d6..HEAD  (four new files under lab/c1-c7-mac-runbook/)
Reviewer:  Cursor Grok (Grok family; author of #436 is Claude)
Prior:     no r1/r2 review of #436; this head ports the #434 r2 A2 fail-closed patch
Verdict:   GO-with-patch
Date:      27 Oct 2026
```

C1-C7 on a Mac stays **NOT RUN ON MAC** until Sash's own `summary.txt`
ends with `C1-C7: PASS.` Do not book from this Linux review. Do not
hand him the unpatched fence: this head can still print `C1-C7: PASS.`
after a `setsid` / `exec -a mds` helper that lives outside the temp
dir sleeps past the 15s quiet period and then rewrites `evidence.txt`
or `summary.txt`, and it can false-FAIL or hang on a real Mac when
Spotlight holds `evidence.txt` or another process's argv contains the
absolute workdir.

Do not merge #436. This review did not push to
`cursor/c1-c7-mac-runbook-5f39`.

## What was reviewed

Detached checkout of
`5f50fc484fcc679c46715340ea5474f9ceec06a9`. Range is only
`ea25c4d6..HEAD`:

| File | Role |
| --- | --- |
| `lab/c1-c7-mac-runbook/README.md` | One ` ```bash ` paste fence, sha/bytes, dry-run table |
| `lab/c1-c7-mac-runbook/dryrun.py` | Linux recorder of that fence (24 cases) |
| `lab/c1-c7-mac-runbook/run.sh` | 32 named tests plus the SBPL probe |
| `lab/c1-c7-mac-runbook/.gitignore` | `evidence.txt`, `probe/` |

No 0.8.0 runtime file, no `capsules/` edit, no `lab/redteam/` edit.

## 1. Paste sha

The only ` ```bash ` fence in `README.md`, body including the
trailing newline, not the markdown fences. Extracted the same way
Sash copies the GitHub / rendered block (text between the fences):

```text
sha256 bfd28dcdd2d8823e31c3d151bf63d0fd84944437c9c104cbfcddb0553ebe1569
bytes  27143
```

Matches README and the #436 PR body.

The fence has no `sudo`, no `curl|sh`, no `elastos serve`, no
`sed -i`, no `readlink -f`, and no GNU `stat -c`. The word `curls`
appears only in the comment "The paste never curls rustup.rs".
`rm -rf` appears once, and only as `rm -rf -- "$c17_workdir"` when
`C17_CLEAN=1` (the default paste leaves the temp folder). Hash uses
`sha256sum --` or `shasum -a 256 --`.

It snapshots `$HOME/.elastos` and the login-home `~/.elastos` and
FAILs if the run creates either path or if a pre-existing tree's
kind/mtime_ns/size/relpath list changes. It does not hash file
contents. `HOME` stays the login home so rustup can write
`~/.rustup`; `XDG_*` points at the temp folder.

## 2. Dry-run, rerun here

This host had no `zsh`. Installed `zsh 5.9` (Ubuntu) so the author's
recorder could run. Then, from `5f50fc48`:

```sh
python3 -I lab/c1-c7-mac-runbook/dryrun.py
```

```text
BLOCK sha256:bfd28dcdd2d8823e31c3d151bf63d0fd84944437c9c104cbfcddb0553ebe1569 bytes:27143
README meta CAUGHT
static sudo CAUGHT
static elastos-serve CAUGHT
static curl-sh CAUGHT
static sed-i CAUGHT
static readlink-f CAUGHT
static gnu-stat CAUGHT
static rustup-skip CAUGHT
static mktemp-trap CAUGHT
static no-single-branch CAUGHT
static pin CAUGHT
static names-fence CAUGHT
static names-run CAUGHT
static cargo-list CAUGHT
static exact CAUGHT
static probe CAUGHT
static ignored-fixture-excluded CAUGHT
static argv-wait CAUGHT
static lsof-quiet CAUGHT
static login-home CAUGHT
static probe-file CAUGHT
happy: last='C1-C7: PASS.' exit=0 CAUGHT
missing-test: last='C1-C7: NOT RUN.' exit=2 CAUGHT
duplicate-row: last='C1-C7: FAIL.' exit=1 CAUGHT
ignored-count: last='C1-C7: FAIL.' exit=1 CAUGHT
exit1-with-pass: last='C1-C7: FAIL.' exit=1 CAUGHT
late-rewrite: last='C1-C7: FAIL.' exit=1 CAUGHT
stale-summary: last='C1-C7: NOT RUN.' exit=2 CAUGHT
missing-pin: last='C1-C7: NOT RUN.' exit=2 CAUGHT
planted-fail: last='C1-C7: FAIL.' exit=1 CAUGHT
elastos-created: last='C1-C7: FAIL.' exit=1 CAUGHT
missing-sandbox-exec: last='C1-C7: NOT RUN.' exit=2 CAUGHT
pass-then-fail: last='C1-C7: FAIL.' exit=1 CAUGHT
setsid-rewrite: last='C1-C7: FAIL.' exit=1 CAUGHT
python-double-fork: last='C1-C7: FAIL.' exit=1 CAUGHT
evidence-symlink: last='C1-C7: FAIL.' exit=1 CAUGHT
lookalike-row: last='C1-C7: FAIL.' exit=1 CAUGHT
cr-row: last='C1-C7: FAIL.' exit=1 CAUGHT
home-redirect: last='C1-C7: FAIL.' exit=1 CAUGHT
existing-elastos-write: last='C1-C7: FAIL.' exit=1 CAUGHT
probe-symlink: last='C1-C7: FAIL.' exit=1 CAUGHT
probe-non-ascii: last='C1-C7: FAIL.' exit=1 CAUGHT
probe-missing: last='C1-C7: PASS.' exit=0 CAUGHT
probe-duplicate: last='C1-C7: PASS.' exit=0 CAUGHT
probe-invalid: last='C1-C7: PASS.' exit=0 CAUGHT
DRYRUN: PASS
C1-C7 booking: NOT RUN ON MAC
```

All 24 author cases CAUGHT. The r2 A2 plants this head added to
`dryrun.py` stay closed.

## 3. Reviewer plants (new; not in dryrun.py)

Recorder: `lab/review-c1-c7-436-r3/plants.py`. Each plant is a stub
remote plus the exact fence under `zsh --no-rcs` 5.9 with the Darwin
`uname` / `xcode-select` shim. Real `/home/ubuntu/.elastos` stayed
absent after cleanup.

CAUGHT here means the fence did not book a false `C1-C7: PASS.` (or,
for the Mac false-FAIL / hang plants, that it did not fail or hang
an honest happy path). SURVIVED means the hole is still open.

| # | Plant | Want | Last line | Result |
| --- | --- | --- | --- | --- |
| 1 | `os.setsid` + `exec -a mds`; helper lives under `/tmp`; sleeps 22s; then writes FAIL | no `C1-C7: PASS.` | `C1-C7: PASS.` then evidence FAIL (26.1s) | **SURVIVED** |
| 1b | same via `nohup` + `setsid` + `exec -a mds`, delay 22s | no `C1-C7: PASS.` | `C1-C7: PASS.` then evidence FAIL | **SURVIVED** |
| 1c | inherited write fd held open during `lsof` (setsid, 8s) | `C1-C7: FAIL.` | `C1-C7: FAIL.` (live writer) | **CAUGHT** |
| 1d | inherited fd closed; reopen the path after 22s | no `C1-C7: PASS.` | `C1-C7: PASS.` then FAIL | **SURVIVED** |
| 1e | `at` / `launchd` / `cron` | no `C1-C7: PASS.` | no `at`/`launchctl` here; same hole as 1 | **SURVIVED** |
| 2a | hard link of `evidence.txt`; rewrite via the other name at 8s | `C1-C7: FAIL.` | `C1-C7: FAIL.` (quiet-period hash moved) | **CAUGHT** |
| 2b | hard link; rewrite via the other name at 22s | no `C1-C7: PASS.` | `C1-C7: PASS.` then FAIL | **SURVIVED** |
| 3 | watcher writes live `evidence.txt` when `evidence.snap` appears | `C1-C7: FAIL.` | `C1-C7: FAIL.` (changed after snapshot) | **CAUGHT** |
| 4 | FAIL journey; detached helper rewrites `summary.txt` to `C1-C7: PASS.` after score | file stays FAIL | file ended `C1-C7: PASS.` | **SURVIVED** |
| 4b | same rewrite through an outside hard link of `summary.txt` | file stays FAIL | file ended `C1-C7: PASS.` | **SURVIVED** |
| 5a | combining acute in `confined` plus real PASS rows | no `C1-C7: PASS.` | `C1-C7: FAIL.` (non-ASCII) | **CAUGHT** |
| 5b | zero-width space in a row name plus real PASS rows | no `C1-C7: PASS.` | `C1-C7: FAIL.` (non-ASCII) | **CAUGHT** |
| 5c | `PASS\x00FAIL` on a wallet row (in-harness `run.sh`) | no false PASS | `C1-C7: NOT RUN.` (no evidence.txt) | **CAUGHT** |
| 6 | same-size overwrite of a pre-existing `~/.elastos` file; `os.utime` restores ns | no `C1-C7: PASS.` | `C1-C7: PASS.` (`plante\n` vs `before\n`) | **SURVIVED** |
| 7 | `HOME` dummy; `run.sh` creates the login-home `~/.elastos` (author replay) | `C1-C7: FAIL.` | `C1-C7: FAIL.` | **CAUGHT** |
| 8 | `C17_SUMMARY` already holds `C1-C7: PASS.` (author replay) | `C1-C7: NOT RUN.` | `C1-C7: NOT RUN.` | **CAUGHT** |
| 9 | read-only fd on `evidence.txt` (`exec -a mds`, 20s) | still `C1-C7: PASS.` | `C1-C7: FAIL.` (lsof treats a reader as a writer) | **SURVIVED** (false FAIL) |
| 10a | unrelated process whose argv contains the absolute workdir | still `C1-C7: PASS.` | waiter hung past 25s | **SURVIVED** (false hang) |
| 10b | unrelated process whose argv contains bare `lab/c1-c7-mac-runbook` | still `C1-C7: PASS.` | `C1-C7: PASS.` | **CAUGHT** |
| 11 | committed `probe/sbpl.out` = `ALLOWED`; `run.sh` never writes the probe | `SBPL_PROBE: NOT RUN` | `C1-C7: PASS.` and `SBPL_PROBE: ALLOWED` | **SURVIVED** |
| 12 | happy probe `DENIED`; detached helper rewrites `ALLOWED` at 22s | booked line stays the measured file | booked `DENIED`; live file later `ALLOWED` | **SURVIVED** |
| 13 | `python3` hidden behind a 127-exit shim | `C1-C7: NOT RUN.` | `C1-C7: NOT RUN.` | **CAUGHT** |
| 14a | `bash -n` and `zsh -n` on the fence; no bash 4-only flags | both clean | both rc 0; no hits | **CAUGHT** |
| 14b | `set -euo pipefail; false \| true` in zsh and bash | both abort | both abort; no `AFTER` | **CAUGHT** |
| 14c | happy path under `bash --noprofile --norc` | `C1-C7: PASS.` | `C1-C7: PASS.` (bash 5.2; no 3.2 on this host) | **CAUGHT** |
| 15 | BSD-portable flags | no GNU-only `sed`/`stat`/`readlink` | absent | **CAUGHT** |
| 16 | `sudo` / `rm -rf` outside the temp dir | none | no `sudo`; one `rm -rf` of `$c17_workdir` when `C17_CLEAN=1` | **CAUGHT** |
| 17 | network beyond `git clone` | clone only | `rustup toolchain install` and `git fetch` of the pin | **SURVIVED** |
| 18 | total runtime bound | a wall clock | wait 7200s; `lsof`, rustup, clone have no timeout | **SURVIVED** |

Plant 1 printed `C1-C7: PASS.` in 26.1s. Eight seconds of linger
later `evidence.txt` was the FAIL fixture. The helper's argv was
`mds -I /tmp/r3-c17-plant-…/rewriter.py`, so the process-group wait,
the `ps` path needle, and `lsof` (file not yet open) all missed it.
The 15s quiet period is a finite window. A 22s sleep walks past it.
`nohup` does not change that. `launchd` / `at` / `cron` are the same
shape: no live process and no open fd at check time.

Plant 1c shows `lsof` does catch a write fd that stays open. Plant
1d closes that fd and opens the path later; it books PASS.

Plant 2a is the author's quiet-period backstop: a hard link is still
a regular file inside the clone (`realpath` stays put), but an 8s
write through the other name moves the hash. Plant 2b waits 22s and
books PASS.

Plant 3 is the TOCTOU between `cp` and the post-score re-hash. The
current post-score check FAILs if live bytes move after the snap.
That window is closed. A write *after* `c17_finish` is plant 1.

Plant 4 is booking by file. The paste's stdout still said
`C1-C7: FAIL.` The helper rewrote `summary.txt` after `c17_finish`.
Sash is told to book from that file. Plant 4b is the same inode
through an outside hard link.

Plant 5a/5b: combining characters and ZWSP are bytes `> 127`, so
the ASCII check FAILs. They cannot sneak a lookalike FAIL past that
check. Plant 5c's in-harness writer failed to create `evidence.txt`
(NOT RUN, not a false PASS). An isolated replay of the fence scorer
rule still treats `PASS\x00FAIL` as PASS (`startswith`); NUL is not
`ord > 127`. That is junk after a real PASS, not a hidden FAIL row
that books C1-C7.

Plant 6 is the leftover `~/.elastos` snapshot: kind, mtime_ns, size,
relative path. Same bytes length and restored nanoseconds book PASS
while the file contents changed.

Plant 9 is a false FAIL on a real Mac. `lsof +D` on
`lab/c1-c7-mac-runbook` treats any open file as a writer, including
a read-only Spotlight / `mds` fd on `evidence.txt`. After a real
cargo run that directory also holds `probe/*.list`. Plant 10a is
worse: the waiter matches the absolute workdir, clone, or lane in
*any* process argv, then waits up to 7200s and FAILs. A decoy
`python3 -c` whose comment contains the workdir hung the paste past
25s. Plant 10b shows the r2 A2 bare-string hole is closed: needles
are already absolute, so `lab/c1-c7-mac-runbook` alone does not hang.

Plant 11 is C1-C7 specific. A committed `probe/sbpl.out` with
`SBPL_PROBE: ALLOWED` and a `run.sh` that never writes the probe
still books `C1-C7: PASS.` with `SBPL_PROBE: ALLOWED`. The probe
line is a measured fact Sash is told to send with the booking.
Plant 12 books `DENIED` and then the live file becomes `ALLOWED`
after `c17_finish`.

Plant 13: a 127-exit `python3` shim is NOT RUN (the version check
fails closed). On a real Mac, `/usr/bin/python3` can be an Xcode
CLT stub that opens a GUI and hangs before a verdict. That hang was
not reproduced here.

`bash -n` / `zsh -n` are clean. This host has bash 5.2, not 3.2;
the fence uses no bash-4-only forms. The documented paste target is
zsh. `set -euo pipefail` plus `false | true` aborts in both shells.

`lsof` missing after the prereq check is fail-closed: the helper
prints `lsof-missing`, which is a non-empty writer list, so the
paste FAILs. A slow `lsof` hangs rather than books PASS.

## 4. Safety

| Check | Result |
| --- | --- |
| `sudo` | Absent from the fence and from `run.sh` |
| Deletes outside the temp dir | One `rm -rf -- "$c17_workdir"` and only when `C17_CLEAN=1`. `run.sh` `rm -f`s the probe write-target under the lane |
| Existing `~/.elastos` | Metadata snapshot (lstat walk). Creation or a metadata change is FAIL. Contents can change undetected (plant 6) |
| Network beyond `git clone` | `rustup toolchain install 1.91.0` when 1.91.0 is missing; `git fetch` of the pin; `git fetch --unshallow` |
| Total runtime bound | Waiter 7200s. `lsof +D`, rustup install, and `git clone` have no timeout. The waiter does not kill leftovers on timeout |

The paste does not run `elastos serve`. Default `C17_CLEAN` leaves
the temp folder. Real `/home/ubuntu/.elastos` was absent after every
plant.

## 5. Findings that need a patch

### F1. `C1-C7: PASS.` after a delayed writer that evades wait and `lsof`

The waiter, the `ps` needle, and `lsof` only see a process that is
still in the group, still names the temp path, or still has the
file open. A helper that `setsid`s, renames argv (`exec -a mds`),
lives outside the temp dir, and sleeps longer than 15s books PASS
and then rewrites `evidence.txt`, `probe/sbpl.out`, or
`summary.txt`. Hard links and `launchd`/`at` are the same hole.
The author's 8s / 12s plants stay CAUGHT because they fire during
the quiet period.

A finite extra sleep does not close this. Freeze the files.

### F2. `~/.elastos` snapshot ignores file contents

`c17_snapshot_tree` records kind, mtime_ns, size, and relative path.
A same-size overwrite with `os.utime` restored books PASS. On
Sash's Mac `~/.elastos` may already exist.

### F3. False FAIL / hang on a real Mac

`lsof +D` on the lane counts readers. The argv waiter uses the
absolute workdir, clone, and lane. Spotlight, or any other process
that names that workdir, can FAIL or hang an honest run. The r2
bare-string hang is already closed.

### F4. SBPL probe can be a previous-run or post-booking file

A committed `probe/sbpl.out` is trusted if `run.sh` does not
overwrite it. A delayed writer can change the live probe after the
booking line. The probe does not write `C1-C7: PASS.`, but Sash
sends that line with the booking.

### F5. Network and wall clock are unbounded

`rustup toolchain install` is extra network. `lsof +D`, clone, and
rustup have no timeout. The 7200s waiter does not kill the cargo
tree when it gives up.

## 6. Exact patch

Apply in the ` ```bash ` fence in `lab/c1-c7-mac-runbook/README.md`,
then recompute the README sha/bytes. Replay plants 1, 4, 6, 9, 10a,
11, and 12 after the edit.

1. **Freeze evidence, probe, and summary before the verdict.** After
   the 15s quiet re-hash, on Darwin run `chflags uchg` on
   `evidence.txt`, `evidence.snap`, `probe/sbpl.out`, `sbpl.snap`,
   and `summary.txt` (create an empty `summary.txt` first if needed,
   freeze it, then write through a replacement and re-freeze, or
   write then freeze and re-hash). A later writer cannot change the
   booking file. Linux dry-run can skip `chflags` when it is
   absent; the Mac paste has it.

2. **Hash `~/.elastos` file contents.** For each regular file in
   the snapshot, also record `sha256`. Keep mtime/size. Skip
   `.DS_Store`, `._*`, and `.localized` so Finder / Spotlight
   metadata does not false-FAIL a pre-existing tree.

3. **`lsof` only `evidence.txt` and `probe/sbpl.out`, and only
   write fds.** Drop `lsof +D` on the lane. Keep `lsof` on those
   two files. Count a line only when the FD column contains `w` or
   `u`. Ignore COMMAND in `mds`, `mdworker`, `mdworker32`,
   `corespotlightd`, `cloudd`, `backupd`, `fseventsd`. Give `lsof`
   a 10s timeout; on timeout, FAIL (not hang).

4. **Argv wait: drop the workdir needle; cap the post-run wait.**
   Keep the absolute clone and the absolute lane. Drop
   `$c17_workdir`. After `run.sh` exits, wait at most 60s for
   leftover argv matches, then FAIL. On the 7200s journey
   deadline, kill the `run.sh` process group.

5. **Refuse a stale probe.** Record whether `probe/sbpl.out` exists
   before `run.sh`. If it existed and its hash is unchanged after
   `run.sh`, treat the probe as `SBPL_PROBE: NOT RUN`. Re-hash
   after the freeze.

6. **Do not install rustup toolchains.** If `1.91.0` is missing,
   `C1-C7: NOT RUN.` The README already asks Sash to install it in
   another window.

Recompute the fence sha/bytes after the edit. Then Sash pastes on
Apple Silicon. Book C1-C7 only on that Mac `summary.txt` ending
`C1-C7: PASS.` Send the `SBPL_PROBE` line with it.

## 7. Principles

- 3 No ambient authority: the paste stays in a temp dir; rustup is
  the documented exception; `rustup toolchain install` still talks
  to the network when 1.91.0 is missing.
- 11 Fail closed, then explain: missing tools and a stale pin stay
  NOT RUN. The 15s quiet period fails open against a later writer.
- 12 Docs, code, tests, and operations must agree: README matches
  the fence sha; C1-C7 stays NOT RUN ON MAC.

## 8. Not proven

- No Apple Silicon paste. BSD `ps` / `lsof` / `chflags` / `dscl`
  were not run on a Mac.
- bash 3.2 is not installed here. Syntax is clean; the paste target
  is zsh.
- `at` / `launchd` are absent on this host. The delay-22 plants are
  the same control flow.
- The Xcode CLT `/usr/bin/python3` stub GUI was not reproduced. A
  missing or 127-exit `python3` is NOT RUN.

## 9. Exact commands run

```sh
python3 - <<'PY'
import hashlib, re
from pathlib import Path
text = Path("lab/c1-c7-mac-runbook/README.md").read_text(encoding="utf-8")
block = re.findall(r"```bash\n(.*?)```", text, flags=re.S)[0].encode("utf-8")
print(hashlib.sha256(block).hexdigest(), len(block))
PY
# -> bfd28dcdd2d8823e31c3d151bf63d0fd84944437c9c104cbfcddb0553ebe1569 27143

sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zsh
# zsh 5.9 (x86_64-ubuntu-linux-gnu)

python3 -I lab/c1-c7-mac-runbook/dryrun.py
# DRYRUN: PASS   (24 cases CAUGHT; 390s)

python3 -I lab/review-c1-c7-436-r3/plants.py
# PLANTS: done
# SURVIVED 14: exec-a-delay22, nohup-exec-a-delay22, inherited-fd-reopen22,
#   launchd-at-cron, hardlink-delay22, summary-rewrite, hardlink-summary,
#   mtime-preserve, mds-reader, argv-abs-hang, probe-stale-allowed,
#   probe-delay22, safety-network, safety-runtime-bound
```

Host: Linux x86_64, Python 3.12.3, rustc 1.91.0, bash 5.2.21, zsh
5.9. Absent: `sandbox-exec`, bash 3.2, `at`, `launchctl`.

## Next

Patch #436 with the six items above. Do not hand Sash this fence
until that head's r3 plants 1, 4, 6, 9, 10a, 11, and 12 are CAUGHT.
C1-C7 stays NOT RUN until his Mac `summary.txt` ends `C1-C7: PASS.`
