# A14 dry run

A14 stays **NOT RUN**. This machine is Linux x86_64. The last line of a real A14 run has to be `A14: PASS` on Sash's Mac, with `summary.txt` from that run. Nothing here is that run.

PR 289 is `cursor/demo-a14-installed-demo-83e1` at `25d524e549439be0757cc672a1d39b0b8459dec2`. The morning steps were executed from `lab/demo-a14/RUNBOOK.md` on that commit. This branch does not change that commit.

The clock on each step is whole seconds (`date +%s`). A `seconds: 0` line means the step finished inside the same second it started.

The byte-for-byte transcript is `dryrun.txt`. The pull in step 2 printed every remote branch because the throwaway clone had never fetched GitHub. That list is lines 43-418 of `dryrun.txt`. The lines that decide the step are quoted below.

## Where the five morning commands stop

Step 2 checks out `spike/agent-host` and fast-forwards it. That branch has no `lab/demo-a14`. Step 3 exits 127. The install script never starts.

On the PR 289 commit, `install.sh --sign` exits 3 in 1 second. It writes an Ed25519 key and then refuses, because this is not macOS and no `--receipt` was given. `run.sh` exits 3. It says the demo is not installed. No `summary.txt` is written. Step 5 calls `open` with an empty path.

The reviewer command in the runbook, `python3 -B -I -m unittest discover -s lab/demo-a14/tests -v`, passed: 50 tests in 1.327s. That is the folder's own unit tests. It is not A14.

## Part A. The five commands, as written

The runbook's first command is `cd ~/code/elastos-agent-host-spike`. That directory was absent. Exit 1, under 1 second, at 2026-10-26T19:42:41Z:

```text
bash: line 1: cd: /home/ubuntu/code/elastos-agent-host-spike: No such file or directory
exit: 1
```

A throwaway clone was then placed at that path so steps 2 to 5 had a repository. The clone is not part of the runbook. It started at `042cb132` on `spike/agent-host`.

Step 1, from the clone, exit 0, under 1 second:

```text
/home/ubuntu/code/elastos-agent-host-spike
## spike/agent-host...origin/spike/agent-host
```

Step 2, `git checkout spike/agent-host && git pull --ff-only`, exit 0, under 1 second. The decisive lines:

```text
Already on 'spike/agent-host'
Your branch is up to date with 'origin/spike/agent-host'.
From https://github.com/Elacity/elastos-agent-host-spike
   042cb132..70bf2de6  spike/agent-host        -> origin/spike/agent-host
Updating 042cb132..70bf2de6
Fast-forward
 capsules/did-provider/CONFINEMENT.md               |   7 +-
 .../tests/fixtures/confine/declared-rights.json    |   2 +-
 capsules/wallet-provider/CONFINEMENT.md            |  12 +-
 capsules/wallet-provider/falsifiers.json           |  34 ++-
 capsules/wallet-provider/src/tests/falsifiers.rs   |   7 +-
 capsules/wallet-provider/tests/confine.rs          |  50 +++-
 .../tests/fixtures/confine/declared-rights.json    |   2 +-
 examples/agent-host/handoff/LOG.md                 |   1 +
 .../reports/provider-mp4-kill-safe-recovery.md     | 265 +++++++++++++++++++++
 9 files changed, 366 insertions(+), 14 deletions(-)
 create mode 100644 examples/agent-host/handoff/reports/provider-mp4-kill-safe-recovery.md
```

HEAD after the pull was `70bf2de6738d786d950c6eec4a053e05704a848c`. An observation command, not a runbook line, printed `DEMO_ABSENT` and `TREE_LACKS_INSTALL`.

Step 3, `bash lab/demo-a14/install.sh --sign`, exit 127, under 1 second:

```text
bash: lab/demo-a14/install.sh: No such file or directory
```

Step 4, `bash lab/demo-a14/run.sh`, exit 127, under 1 second:

```text
bash: lab/demo-a14/run.sh: No such file or directory
```

Step 5, the `open` command from the runbook, exit 1, under 1 second. `ls` could not see `~/Library/Application Support/elastos-demo-a14/runs/*/`. The command substitution was empty, so `open` ran with no path. On this VM `open` is `xdg-open`, and it printed its usage.

`spike/agent-host` moved again after that pull, to `23d27d8e8e3ff6148315a86c5ef9187f89dd1e01`. `70bf2de6` is an ancestor of that commit. `lab/demo-a14/install.sh` is still absent there. The demo commit is not an ancestor of it. The merge-base of the demo commit and this line is `fe1e1c7e7aea6bbcd55f0042202a17861a428ad4`, and this line is 67 commits after that merge-base.

The handover in this repository names the Mac checkout as `/Users/sash/code/wt-agent-host`. The runbook's `cd` uses `~/code/elastos-agent-host-spike`. Those are different paths.

## Part B. The same install and run on the PR 289 commit

Worktree `/tmp/pr289-demo-a14`, detached at `25d524e549439be0757cc672a1d39b0b8459dec2`, clean (`git status --porcelain` length 0). Step 2 was not repeated here. Repeating it would leave this commit.

`bash lab/demo-a14/install.sh --sign`, exit 3, 1 second, 2026-10-26T19:42:42Z to 2026-10-26T19:42:43Z:

```text
Installing the A14 demo into /home/ubuntu/.local/share/elastos-demo-a14/current
Signing is on: this machine's key is /home/ubuntu/.local/share/elastos-demo-a14/signing/receipt-signing.key (it proves VERSIONS.json and INSTALL.json are unchanged since install on this machine; it does not prove who published them).
REFUSED: no VERSIONS.json for this machine.
  - VERSIONS.json comes from lab/agent-conformance/run.sh, which runs on macOS only; on this machine give --receipt PATH
Next: fix the item above, then run `bash lab/demo-a14/install.sh` again.
```

The key was written even though the install then refused. Modes, and nothing else:

```text
755 d /home/ubuntu/.local/share/elastos-demo-a14
700 d /home/ubuntu/.local/share/elastos-demo-a14/signing
600 f /home/ubuntu/.local/share/elastos-demo-a14/signing/receipt-signing.key
644 f /home/ubuntu/.local/share/elastos-demo-a14/signing/receipt-signing.key.pub
```

`~/Library/Application Support/elastos-demo-a14` did not exist. The Mac path in the runbook is not the path this OS uses. The script's own choice for Linux is `~/.local/share/elastos-demo-a14`.

`bash lab/demo-a14/run.sh`, exit 3, under 1 second:

```text
A14 installed demo: /home/ubuntu/.local/share/elastos-demo-a14/current
REFUSED: the demo is not installed. No journey was run.
  - no installed demo at /home/ubuntu/.local/share/elastos-demo-a14/current; run lab/demo-a14/install.sh first
Next: run `bash lab/demo-a14/install.sh`, then run this command again.
```

No `runs/` directory and no `summary.txt`. The checkout stayed clean. The demo home, including the key, was removed after the modes were recorded. That removal is not a runbook step.

Step 5 failed the same way as in Part A: `ls` missed the Library path, and `open` received no path.

No journey ran. The output never contained `A14: PASS` or `A14: NOT RUN`. The refusal returns before that line.

## Part C. The runbook's reviewer command

```text
Ran 50 tests in 1.327s
OK
exit: 0
seconds: 1
```

## What this VM could not do

The conformance run, the guest build, and the journey tests were not started. `install.sh` returns before step 1 of 5 when the OS is not macOS and `--receipt` is absent. A synthetic receipt would be a different command from the one in the morning steps.

Bash here is 5.2.21. macOS `/bin/bash` 3.2 was not executed. `bash --posix -n` accepts `install.sh` and `run.sh` on this Bash. That is a parse check, not a 3.2 run.

## Preflight on this VM

Recorded on commit `129f4cb875a13dfde5ea00e2de18d02a434dbe43`, clean tree, with `dash`. `bash --posix` printed the same preflight text on the earlier run. The script does not install, delete, or write a receipt. `git status` and the index mtime were the same after the run.

`dash lab/a14-dryrun/preflight.sh` exited 1. Exact output:

```text
missing: operating system is Linux; A14's VERSIONS.json is produced on macOS
missing: architecture is x86_64; A14 needs native Apple Silicon (arm64)
missing: lab/demo-a14/install.sh is not in this checkout; morning step 2 leaves spike/agent-host, and that branch has no demo until PR 289 is merged
missing: lab/demo-a14/run.sh is not in this checkout; morning step 2 leaves spike/agent-host, and that branch has no demo until PR 289 is merged
missing: lab/demo-a14/demo.py is not in this checkout; morning step 2 leaves spike/agent-host, and that branch has no demo until PR 289 is merged
missing: lab/demo-a14/RUNBOOK.md is not in this checkout; morning step 2 leaves spike/agent-host, and that branch has no demo until PR 289 is merged
missing: lab/demo-a14/journeys.json is not in this checkout; morning step 2 leaves spike/agent-host, and that branch has no demo until PR 289 is merged
missing: wasm32-unknown-unknown is not installed for 1.91.0; the guest build needs it, and the five morning steps do not add it
missing: /usr/bin/sandbox-exec is missing; the C1-C7 steps run provider profiles with this macOS program
missing: /usr/sbin/lsof is missing; the conformance run checks earlier homes with this path
preflight: FAIL
```

`/usr/bin/shasum`, `ssh-keygen`, `python3 -I`, git, and free space were present, so they produced no line.

`dash lab/a14-dryrun/falsify.sh` builds a `PATH` with the other tools and without `ssh-keygen`. Exact output, exit 0:

```text
falsifier: control preflight took 0.059 seconds
falsifier: CAUGHT
plant: PATH with no ssh-keygen (hidden=yes)
planted exit: 1 in 0.067 seconds
caught line: missing: ssh-keygen is not on PATH (install.sh --sign uses it to sign the receipts)
restored PATH does not report that line
git status and the index mtime stayed the same
```

Before that commit, deleting the `need_cmd ssh-keygen` line made the falsifier exit 1, and the planted output had no ssh-keygen line. Restoring the line made it print `falsifier: CAUGHT` again.

On the Mac, from a checkout of this branch:

```sh
sh lab/a14-dryrun/preflight.sh
```

To point it at a checkout of PR 289:

```sh
sh lab/a14-dryrun/preflight.sh /path/to/the/demo/checkout
```

A Mac that already has every prerequisite prints `preflight: OK` and exits 0.
