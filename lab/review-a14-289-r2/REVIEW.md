# Adversarial review r2 of PR 289 (A14 morning runbook)

Draft. Do not merge. A14 itself is **NOT RUN**. Only Sash's Mac run counts.
PR 289's branch was not edited, not pushed, and not commented on.

```text
Slice:        r2 independent review of PR 289 after the #366 NO-GO fixes
Branch / PR:  cursor/review-a14-289-r2-944d
Read:         https://github.com/Elacity/elastos-agent-host-spike/pull/289
Claimed head: e6651b29becaca6db12065413169e2fafce6cd64
Actual head:  e6651b29becaca6db12065413169e2fafce6cd64   (matches)
Author dry run: f721ec794f1fb4d17afc716459e6bbf006257093
#366 review:  a4fab5b8 against then-head 39b4b47e
Machine:      Linux x86_64, Python 3.12.3, rustc 1.91.0, zsh 5.9, bash 5.2.21
```

Work is only under `lab/review-a14-289-r2/`. A detached worktree at `e6651b29` was used to read, mutate, and restore. Morning steps ran in new folders under this review tree.

**Verdict for handing Sash this block as written: NO-GO.**

The seven #366 findings are fixed in the code. 76 unit tests passed. 48/48 named falsifiers were CAUGHT. Ten fresh mutants for those seven findings were CAUGHT. That is not enough to hand him the fence as the first thing he pastes. The exact block dies on a private HTTPS clone when GitHub credentials are missing, and it dies at preflight (exit 1, no `this-run`) when the one-time wasm target is still missing. The author's Linux dry run is the same `lab/demo-a14` bytes as this head, and it is not the pasted script.

## Head SHA and the author's dry run

GitHub PR 289, `origin/cursor/demo-a14-installed-demo-83e1`, and the detached worktree all resolve to:

`e6651b29becaca6db12065413169e2fafce6cd64`

The author's dry run cites `f721ec79`. That commit is the parent of this head. `git merge-base --is-ancestor` is true. The only files that changed after `f721ec79` are `examples/agent-host/handoff/LOG.md` and `examples/agent-host/handoff/reports/A14-morning-nogofix.md`. `lab/demo-a14` is byte-identical on the two commits.

So the dry run is evidence for the same demo code as the pushed head. It is not evidence for the pasted morning block:

- The author kept going after `preflight: FAIL` and ran `install.sh` / `run.sh` as separate commands.
- The fence is one `set -euo pipefail` script. A failing preflight is exit 1. The script stops. `install.sh` never runs. `this-run` and `summary.txt` are never written.

The PR summary and RUNBOOK fences match (1188 bytes). `tools/morning-block.sh` is that fence.

## The exact block on this Linux VM

HOME was pointed at a review scratch folder so the walk did not touch the real home.

### Walk 1 — default HTTPS URL, no GitHub helper

`A14_REMOTE` unset. Isolated HOME, so this VM's token rewrite was gone.

```text
fatal: could not read Username for 'https://github.com': No such device or address
bash block exit: 128
clone dest exists: no
Library this-run: absent
any summary.txt under HOME: 0
```

Transcript: `evidence/morning-block.txt`, `evidence/morning-block-stderr.txt`.

A second clone with an empty gitconfig and `GIT_TERMINAL_PROMPT=0` ended the same way: exit 128, dest absent. Transcript: `evidence/clone-unauth-clean.txt`.

The default URL is `https://github.com/Elacity/elastos-agent-host-spike.git`. This repository is private. A Terminal with no HTTPS helper stops here and asks for a username.

### Walk 2 — local `A14_REMOTE` so clone can finish

`A14_REMOTE=/tmp/a14-289-head` (the reviewed commit, local branch of the same name).

```text
clone HEAD: e6651b29becaca6db12065413169e2fafce6cd64
clone branch: cursor/demo-a14-installed-demo-83e1
install.sh present; porcelain empty
preflight: FAIL
bash block exit: 1
Library this-run: absent
XDG this-run: absent
summary count under HOME: 0
```

The same bytes under zsh 5.9: exit 1, clone at `e6651b29`, no `this-run`. Transcripts: `evidence/morning-block-local.txt`, `evidence/morning-block-zsh.txt`.

The user-facing expectation for this Linux path was "preflight FAIL, exit 3, summary.txt via this-run". The pasted script produces exit 1 and no summary. Exit 3 and `this-run` appear only when `install.sh` is started by hand after the block has already stopped.

### Install by hand after the block (author's dry-run shape)

From the fresh clone, with `DEMO_A14_HOME` isolated:

- `install.sh --sign` → exit 3, `REFUSED: this machine is not ready.`, no signing key, no `current/`, `this-run` present, `summary.txt` present.
- `CARGO_TARGET_DIR=../elsewhere` is named on that list. Key still absent.
- `run.sh` → exit 3, new `summary.txt`, `this-run` moved to that folder.
- Step 5 as written (Library path under the isolated HOME): `open` not invoked.

Transcripts: `evidence/continue-past-preflight.txt`, `evidence/install-elsewhere-target.txt`.

## Tests re-run here

```text
python3 -B -I -m unittest discover -s lab/demo-a14/tests -v
  -> Ran 76 tests in 1.540s  OK
git diff --check
  -> clean
planted every entry in lab/demo-a14/falsifiers.json
  -> 48 CAUGHT of 48, then suite OK
  -> mutants/all_claimed.json
sh lab/demo-a14/falsify.sh
  -> falsifier: CAUGHT (ssh-keygen PATH plant, 0.056s)
```

## The seven #366 findings, each with a fresh mutant

Each plant is a different edit than F-A14al..av. Mutating the named guard made the named tests fail. Restore brought the suite back. Results: `mutants/fresh_findings.json`.

| # | #366 finding | Author claim | Verdict | Fresh mutant |
| --- | --- | --- | --- | --- |
| 1 | Step 1 ran `git checkout` in an existing clone | Fresh `git clone --branch` into a new folder; refuse if dest exists | **HOLDS** | `git checkout "$branch"` CAUGHT (X366-1-CHECKOUT-VAR). `git switch cursor/...` CAUGHT (X366-1-SWITCH). F-A14al, F-A14as CAUGHT. |
| 2 | Five lines kept going after a failed step | One `set -euo pipefail` block | **HOLDS** | Dropping only `-e` CAUGHT (X366-2-DROP-E). F-A14ar, F-A14av CAUGHT. Side effect: a failed preflight is now exit 1 and `install.sh` never runs. |
| 3 | `CARGO_TARGET_DIR=../elsewhere` accepted | Collapse `..` and refuse a path outside the checkout | **HOLDS** | Skipping `normpath` CAUGHT (X366-3-NO-DOTDOT). Live install named `CARGO_TARGET_DIR=../elsewhere`. F-A14aj CAUGHT. |
| 4 | Install's ready list was shorter than preflight | Default ready is `preflight_problems()` | **HOLDS** | Default ready as an empty lambda CAUGHT (X366-4-EMPTY-READY). F-A14an CAUGHT. |
| 5 | Failed write after builds left the new key | Remove only the key this run created | **HOLDS** | Always-remove CAUGHT (X366-5-ALWAYS-REMOVE). Treating an existing key as `created_key` CAUGHT (X366-5-SKIP-CREATED-FLAG). `test_failed_write_keeps_a_preexisting_key` stays green. F-A14ap CAUGHT. |
| 6 | Install refusals wrote no summary; step 5 opened yesterday | Every install refusal writes `summary.txt` and `this-run`; step 5 reads that pointer | **HOLDS in demo.py** | Skipping `mark_this_run` CAUGHT (X366-6-NO-MARK). `ls -dt` in step 5 CAUGHT (X366-6-LS-DT). F-A14aq, F-A14am, F-A14au CAUGHT. The pasted script never reaches this path when preflight fails. |
| 7 | `A14: PASS.` could print without `summary.txt` | PASS path must write `this-run` / `summary.txt` | **HOLDS** | Writing `notes.txt` instead of `summary.txt` CAUGHT (X366-7-OTHER-NAME). F-A14ao CAUGHT. |

None of the seven claims are FALSIFIED.

## New morning-breakers

### 1. Private HTTPS clone (the one that stops him first)

The fence's default URL is HTTPS to a private repository. With no helper, `git clone` asks for a username or exits 128. The dest folder is left absent, so a retry with a new timestamp works. A retry with a fixed `A14_CLONE` also works here because dest was not created.

The fence has `A14_REMOTE`, and the human lines never say this repository is private or when to set that variable. If his Terminal uses SSH remotes and has no HTTPS login, the paste stops before preflight.

### 2. The fence stops at preflight; the one-time wasm add sits under the fence

`preflight.sh` exits 1 on FAIL. `set -e` ends the script. That is the intended "stop on FAIL". It also means the paste never writes `this-run`.

The RUNBOOK then says, later, to add `wasm32-unknown-unknown` "the first time only", and preflight itself says "the five morning steps do not add it". If he pastes first and that target is missing, he gets `preflight: FAIL` and the script ends. A second paste with the default timestamp dest clones again. A second paste with the same `A14_CLONE` is refused because the first clone left that folder.

On a Mac that already has the one-time tools, preflight can pass and the rest of the fence can run. This review did not have that Mac.

### 3. `A14_CLONE` reuse

The dest-exists check works. An existing folder prints `REFUSED` and exits 3. A missing dest is accepted. Transcript: `evidence/a14-clone-reuse.txt`. This is the designed refusal. It becomes a trap only when he sets `A14_CLONE` to the folder from a failed first paste.

### 4. `this-run` pointing at a stale run

Step 5 reads `this-run`. A leftover pointer to an old `summary.txt` would open that old file. The pasted script never reaches step 5 unless install and run both return 0, and those commands rewrite `this-run`. So the fence itself does not open yesterday's folder. Running step 5 by hand after an old install would.

### 5. Key removal deleting a pre-existing key

`created_key` is true only when this run created the file. A failed write then deletes that key and says so. A key that was already there stays. Both fresh mutants for the opposite bug were CAUGHT. This one holds.

### 6. `open` on a `.txt`

On macOS, `open path/to/summary.txt` opens the default editor. The path is quoted. That is fine. This Linux VM's `open` is `xdg-open`; the fence never reached it.

### 7. `set -u`, `date`, zsh, macOS bash 3.2

With `A14_CLONE` and `A14_REMOTE` unset, both zsh 5.9 and bash 5.2 expand the dest line and keep going. Transcript: `evidence/zsh-set-u-clean.txt`. The full fence under zsh cloned and stopped at preflight the same way as bash.

`date +%Y%m%d-%H%M%S` is valid on GNU date and on BSD date. macOS `/bin/bash` 3.2 has `set -o pipefail` and `${var:-default}`. This review did not start a real bash 3.2 binary.

## NOT RUN (only a real Mac can prove)

- A14 itself (`A14: PASS.` from `run.sh` with `summary.txt` from that run)
- Native arm64 Terminal, real Rosetta, `/usr/bin/sandbox-exec`, macOS `/usr/bin/shasum`, `/usr/sbin/lsof`, macOS `open`
- A 40 GB disk refusal on a Mac that is actually low on disk
- `com.apple.quarantine` on a browser zip
- macOS `/bin/bash` 3.2 and the stock macOS zsh
- `xcode-select` on a Mac without the tools
- HTTPS clone on a Mac that already has `gh auth` or a credential helper

## Principles

- 6 Clear user / operator / developer boundaries: a new folder is used; existing trees stay put. The first line he pastes still has to be able to clone this private repository.
- 11 Fail closed, then explain: Linux preflight fails closed. The paste then stops, so `this-run` is not written. The `missing:` lines in the terminal are the explanation.
- 12 Docs, code, tests, and operations must agree: the seven #366 claims now have tests. The PR's Linux dry run does not match the pasted script. The one-time wasm add sits under the paste.

## What to change before handing him the block

Keep the seven code fixes. Change only the human start of `lab/demo-a14/RUNBOOK.md` (and the matching fence in the PR summary):

1. Put the "What you need, one time" list **above** the paste fence, including `rustup target add wasm32-unknown-unknown`.
2. Add two comment lines in the fence, just above `url=`:

```bash
# This repository is private. If git asks for a password, Ctrl-C and rerun with:
#   A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git
```

Leave `set -euo pipefail` in place. A failed preflight should still stop the script. In the PR text, say that a Linux paste ends at preflight (exit 1) and that `this-run` comes from `install.sh` when that command is started on its own.

Do not put `git checkout` back. Do not reopen an existing tree.

## Next

Owner of PR 289 applies those two RUNBOOK edits. This review stays draft. Book A14 only when Sash's Mac prints `A14: PASS.` and `summary.txt` is from that run.
