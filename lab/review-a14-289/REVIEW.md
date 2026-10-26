# Adversarial review of PR 289 (A14 morning runbook)

Draft. Do not merge. A14 itself is **NOT RUN**. Only Sash's Mac run counts.

```text
Slice:        independent review of PR 289 A14 morning runbook
Branch / PR:  cursor/review-a14-289-8a2f
Read:         https://github.com/Elacity/elastos-agent-host-spike/pull/289
Head:         39b4b47edc64d8705a0294c978e6171819cea9fc
Parent:       25d524e549439be0757cc672a1d39b0b8459dec2
Earlier dry run: PR 321 FIXES.md (9 items)
Machine:      Linux x86_64, Python 3.12.3, OpenSSH via ssh-keygen, rustc 1.91.0
```

Work is only under `lab/review-a14-289/`. PR 289's branch was not edited, not pushed, and not commented on. Other `lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, and elastos-runtime were left alone.

**Verdict for handing Sash this runbook as written: NO-GO.**

The nine fixes from PR 321 are in the tree and their named falsifiers fail. A clean full clone can reach the demo files. Linux then stops before any build or key. That is not enough. Step 1 still runs `git checkout` inside the clone he already has, and the five commands keep going after a failed checkout.

## How this review was done

A detached worktree at `39b4b47e` was used only to read and to mutate, then restore. Morning steps were run in new clones under this folder, never in `/workspace` on `spike/agent-host`.

Reviewer contamination: `rustup show` in `/workspace` auto-installed toolchain `1.91.0-x86_64-unknown-linux-gnu`. After that, `rustc` existed and `wasm32-unknown-unknown` did not. Install then named the missing wasm target. It still refused before `cargo fetch` and wrote no key. That install was not started by the runbook.

## The five morning steps, as written

### Step 1 on a single-branch clone (this VM's first try)

`git fetch origin cursor/demo-a14-installed-demo-83e1` wrote `FETCH_HEAD` at `39b4b47e` and did not create a remote-tracking branch. Then:

```text
error: pathspec 'cursor/demo-a14-installed-demo-83e1' did not match any file(s) known to git
```

`git pull --ff-only` ran on `spike/agent-host` and said already up to date. Porcelain was empty. `test -f lab/demo-a14/install.sh` printed nothing and the later commands still ran. Preflight: `cannot open lab/demo-a14/preflight.sh`. Install and run: exit 127. This is the same class of miss that PR 321 found, now after a failed checkout instead of a checkout of `spike/agent-host`.

Transcript: `evidence/dryrun-single-branch.txt`.

Sash's `wt-agent-host` is almost certainly a full clone. This case still matters: the runbook lines are not joined with `&&`, so any failed checkout continues.

### Step 1 on a normal full-refspec clone

Same fetch then checkout created `origin/cursor/demo-a14-installed-demo-83e1`, switched to that branch at `39b4b47e`, and `lab/demo-a14/install.sh` was present. Porcelain empty.

### Steps 2 to 5 on that full clone

`DEMO_A14_HOME` was set to `lab/review-a14-289/scratch/demo-home-full` so this VM did not write `~/.local/share/elastos-demo-a14`.

**Step 2** `sh lab/demo-a14/preflight.sh` in 0s, exit 1:

```text
missing: operating system is Linux; A14's VERSIONS.json is produced on macOS
missing: architecture is x86_64; A14 needs native Apple Silicon (arm64)
missing: wasm32-unknown-unknown is not installed for 1.91.0; the guest build needs it, and the five morning steps do not add it
missing: /usr/bin/sandbox-exec is missing; the C1-C7 steps run provider profiles with this macOS program
missing: /usr/sbin/lsof is missing; the conformance run checks earlier homes with this path
preflight: FAIL
```

**Step 3** `bash lab/demo-a14/install.sh --sign` in 0s, exit 3:

```text
REFUSED: this machine is not ready.
  - wasm32-unknown-unknown is not installed for 1.91.0; the guest build needs it, and the morning steps do not add it
```

No signing key. No `current/`. Default XDG and Library demo folders stayed absent. No `cargo fetch`.

**Step 4** `bash lab/demo-a14/run.sh` in 0s, exit 3. Wrote `runs/*/summary.txt` and named that path in `Next:`.

**Step 5 as written** (Library path): `open` was not invoked.

**Step 5 pointed at the isolated demo home:** the guard would open the new run folder. `summary.txt` was there and said the demo is not installed.

Transcript: `evidence/dryrun-full-clone.txt`.

### Dirty existing tree

A full clone on `spike/agent-host` with a modified `README.md` and an untracked file still ran `git checkout cursor/demo-a14-installed-demo-83e1` and succeeded. The dirt came along. `install.sh` was present. Porcelain was not empty.

Evidence: `evidence/dirty-checkout.txt`.

## Tests re-run here

```text
python3 -B -I -m unittest discover -s lab/demo-a14/tests -v
  -> Ran 66 tests in 1.432s  OK
git diff --check
  -> clean
sh lab/demo-a14/falsify.sh
  -> falsifier: CAUGHT (ssh-keygen PATH plant, 0.065s)
```

Every entry in `lab/demo-a14/falsifiers.json` was planted, required to fail, and restored: **39/39 CAUGHT**. See `mutants/all_claimed.json`.

## Verdict per claimed fix

Mutating the named guard made its named test fail for every item below that says CAUGHT. A surviving extra mutant is WEAK.

| # | Claim in PR 289 | Verdict | Proof |
| --- | --- | --- | --- |
| 1 | Step 1 checks out the demo branch and checks `install.sh` exists | **WEAK** | F-A14al CAUGHT. Full clone does check out `39b4b47e`. The test is a string match. Adding `git reset --hard` still passed (`X-RUNBOOK-RESET` SURVIVED). Step 1 still runs `git checkout` in the clone he already has. A failed checkout does not stop the later lines. |
| 2 | Both known paths are examples; stop if `install.sh` is missing | **HOLDS** | RUNBOOK names `/Users/sash/code/wt-agent-host` and `~/code/elastos-agent-host-spike` as examples. `test_runbook_stays_on_the_demo_branch` requires both. The stop is a comment plus `test -f`; a pasted block still continues. |
| 3 | `preflight.sh` is step 2; `machine_problems()` runs before fetch and before any key | **HOLDS** | F-A14ad, F-A14ak CAUGHT. Fresh full-clone install exited 3 in 0s with no fetch and no key. `test_machine_problems_does_not_start_rustup` passed. Install's list is shorter than preflight (see finding 4). |
| 4 | Signing key is written only just before install write | **HOLDS** | F-A14ae CAUGHT. Linux `--sign` without a receipt wrote no key. Machine-not-ready wrote no key. A later `write_install` failure still leaves a key (new finding 5). |
| 5 | A refused run writes `summary.txt`; step 5 opens only a real path | **HOLDS** | F-A14af, F-A14am CAUGHT. Step 4 wrote `summary.txt` and named it. Library `open` was not invoked when that path was empty. The PASS-path `write_summary` can be deleted and tests still pass (`X-PASS-SUMMARY` SURVIVED). Install refusals write no summary. |
| 6 | Outside `CARGO_TARGET_DIR` refused; `CARGO_TERM_COLOR=never` | **WEAK** | F-A14aj, F-A14ag CAUGHT. Absolute `/tmp/...` is refused by both preflight and `machine_problems`. `CARGO_TARGET_DIR=../elsewhere` is accepted by both (`probes.json`, `evidence/preflight-probes.txt`). `test_relative_cargo_target_dir_is_allowed` pins a relative name as allowed. |
| 7 | Rosetta shell refused; say "open a native arm64 Terminal" | **HOLDS** / **NOT RUN** on a Mac | F-A14ah CAUGHT with injected `translated="1"`. `proc_translated()` is never called by that test (`X-ROSETTA-SYSCTL-FAIL-OPEN` SURVIVED). On this Linux VM `proc_translated()` returned `"0"`. |
| 8 | Space in HOME, checkout, `CARGO_HOME`, or rustc sysroot refused | **WEAK** | F-A14ai CAUGHT for HOME. A probe also refused a space in `CARGO_HOME`. Removing the checkout path from the loop left `test_space_in_home_is_refused` green (`X-SPACE-CHECKOUT-ONLY` SURVIVED). `/Users/sash` has no space. |
| 9 | Use git clone/checkout; preflight reports quarantine and does not strip it | **WEAK** | The sentence is in RUNBOOK. Disabling the `xattr` block in `preflight.sh` left the unit tests green (`X-QUARANTINE-PREFLIGHT` SURVIVED). Only `install.sh`, `run.sh`, and `demo.py` are checked. **NOT RUN** on a Mac. |

None of the nine claims are FALSIFIED. The named plants fail. The weak ones are incomplete proofs or holes next to the fix.

## New findings, most likely to break the morning first

1. **Step 1 changes git state in the clone he already has.** The runbook says `cd` to that clone, then `git checkout cursor/demo-a14-installed-demo-83e1`. That is the failure mode this review was told to look for. Sash's rule is that existing working trees keep their git commands. On a clean full clone the checkout works, so his `wt-agent-host` tree would move off whatever branch it is on. On a dirty tree the checkout still succeeded and carried the dirt onto the demo branch.

2. **The five lines are not one script.** There is no `set -e` and no `&&`. A failed `git checkout` still runs `git pull`, `git status`, `test -f`, then steps 2 to 5. Proven on a single-branch fetch. Same shape as PR 321 item 1.

3. **`CARGO_TARGET_DIR=../elsewhere` is accepted.** Preflight prints no `CARGO_TARGET` line. `machine_problems()` returns []. An absolute outside path is refused. If his shell has a relative target dir above the repo, the long install can record executables from the wrong place, or refuse only after the conformance run.

4. **Install's early check is not the same list as preflight.** `machine_problems()` does not look for `ssh-keygen`, Xcode command line tools, `curl` / crates.io, or `python3`. Those are preflight-only. If step 2 is skipped, a Mac can spend the long conformance run and then fail at signing or at `xcode-select`.

5. **A failed write after the builds leaves the signing key.** Probe `key_left_after_write_install_fails`: `write_install` returned `"disk full"`, exit 3, no `current/`, key existed at mode 0600. The PR 321 fix moved the key after the builds. A failure at copy time still leaves it. The next run then treats signing as on.

6. **Install refusals write no `summary.txt`.** Only `run.sh` does. If he stops at step 3, step 5 has nothing new. If an old run folder exists, step 5 opens the newest one, which may be yesterday's.

7. **`A14: PASS.` can be printed without a test that requires `summary.txt`.** Today's code writes the file on the PASS path (probe `pass_writes_summary`). `test_matching_run_walks_every_step` does not mention `summary`. Deleting that `write_summary` call still passed.

## Other holes (lower chance tomorrow morning)

- Preflight uses `awk` and `df` without a `need_cmd` line. A missing `awk` would abort the script instead of printing `missing:`. macOS has `awk`.
- Preflight's crates.io check is `curl --max-time 2`. This VM answered in 0.029s. Slow wifi could print `preflight: FAIL` on an otherwise ready Mac.
- Step 5 is hardcoded to `~/Library/Application Support/elastos-demo-a14/runs/`. `DEMO_A14_HOME` is ignored there. The morning runbook does not set that variable.
- `inside()` does not resolve symlinks. Not exercised here.

## NOT RUN (only a real Mac can prove)

- A14 itself (`A14: PASS.` from `run.sh` with `summary.txt` from that run)
- Native arm64 Terminal vs a real Rosetta shell (`sysctl.proc_translated`)
- `/usr/bin/sandbox-exec`, `/usr/sbin/lsof`, macOS `/usr/bin/shasum`
- 40 GB disk refusal on a Mac that is actually low on disk
- `com.apple.quarantine` on a browser zip
- macOS `/bin/bash` 3.2 and `open`
- `xcode-select` on a Mac without the tools
- A worktree that already has `cursor/demo-a14-installed-demo-83e1` checked out

## Principles

- 6 Clear user / operator / developer boundaries: the morning steps must not take over an existing working tree.
- 11 Fail closed, then explain: Linux did fail closed before fetch and key. A failed checkout does not fail closed.
- 12 Docs, code, tests, and operations must agree: the runbook, `machine_problems()`, and preflight do not share one list. Several claims are pinned only as RUNBOOK strings.

## What to change before handing him the runbook

Step 1 has to leave his existing trees alone. Use a new folder or a new `git worktree add`, fetch the demo branch into that folder, and stay there. Join the step-1 lines with `&&` and stop when `install.sh` is missing.

Then keep steps 2 to 5. Refuse a `CARGO_TARGET_DIR` that resolves above the repository, including `../...`. Make install's ready list match preflight for `ssh-keygen` and Xcode tools. Pin `summary.txt` on the PASS path. Remove a new key if `write_install` fails.

## Next

Owner of PR 289 rewrites step 1. This review stays draft. Book A14 only when Sash's Mac prints `A14: PASS.` and `summary.txt` is from that run.
