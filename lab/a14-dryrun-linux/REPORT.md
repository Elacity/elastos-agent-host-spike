# A14 Linux dry-run of the morning runbook

**Verdict: GO-with-patch** for Sash's Mac run.

A14 itself is still **NOT RUN**. Book it only when Sash's Mac prints `A14: PASS.` and `summary.txt` is from that run.

This branch only adds `lab/a14-dryrun-linux/`. It does not edit `lab/demo-a14`, BACKLOG.md, lane.env, scripts, or any 0.8.0 runtime code.

| Field | Value |
| --- | --- |
| Runbook | PR #289 `cursor/demo-a14-installed-demo-83e1` at `3bff62b9702435ceb435789e24ecdf8ab5ae9cab` |
| Fresh clone | `/tmp/a14-dryrun-src-20261026-232436`, detached at that SHA |
| Morning clone | `/home/ubuntu/a14-run-20261026-232441`, same SHA, clean tree |
| Machine | Linux x86_64, bash 5.2, zsh 5.9 (installed here only to test the paste) |
| Recorder | `lab/a14-dryrun-linux/dryrun.sh` |
| Line-by-line wall clock | **9.722 s** (2026-10-26T23:24:36Z to 23:24:46Z) |
| Whole-block bash | 3.124 s, exit 1 at preflight, `this-run` unchanged |
| Whole-block zsh | 3.040 s, exit 1 at preflight, `this-run` unchanged |
| Draft PR | https://github.com/Elacity/elastos-agent-host-spike/pull/405 |

The recorder wraps each morning unit in `set +e` so a failing line still gets an exit code. A real paste of the whole fence starts with `set -euo pipefail` and **stops at preflight** on this OS. That was confirmed with the fence copied into `bash` and into `zsh`.

Reproduce:

```bash
python3 lab/a14-dryrun-linux/dryrun.sh --out lab/a14-dryrun-linux
```

## Verdict

The morning fence, copied as written, does what the runbook says on Linux: clone a new folder, refuse a dirty tree, then stop at `preflight: FAIL`. It does not start a 30-minute install when pasted as one script. It does not write a signing key. It does not print `A14: PASS.`

No command in the fence failed for a reason that would also stop a ready Mac. The two wording gaps below can stall a non-developer. They do not change the paste. Apply `PROPOSED-RUNBOOK-PATCH.diff` on #289 if you want those lines clearer before the Mac run. The fence itself can stay as it is.

## Breaker list

Hard breakers that would stop Sash on a ready Mac: **none seen**.

| Item | Class | Why |
| --- | --- | --- |
| rustup.rs "run the one command it shows" | AMBIGUOUS | The runbook does not print the installer. This machine already had rustup, so the installer was not re-run. |
| "A brand-new clone made by the morning block" | AMBIGUOUS | A reader can clone by hand first, then paste, and get two clones. The paste still makes its own folder. |
| Private HTTPS clone | note | This VM rewrites `github.com` HTTPS through stored credentials, so `git clone` did not ask for a password. The fence already says to Ctrl-C and set `A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git` if git asks. Sash needs his usual GitHub login. |

## NOT RUN list (macOS-only, expected)

| Step | Reason |
| --- | --- |
| Mac with 40 GB free | Requirement is macOS. This Linux volume has 244.8 GiB free (preflight treats 40 GB as 40 GiB). |
| Terminal.app | No Applications/Utilities on Linux. |
| `xcode-select --install` | Command missing (exit 127). |
| Darwin-only preflight rows | Xcode CLT, `open`, Rosetta, `com.apple.quarantine`. Not evaluated off Darwin. |
| `install.sh --sign` journeys | Whole-block paste never reaches this. Line-by-line start refused in 0.414 s with the same four Linux gaps. No signing key. |
| `run.sh` journeys | Whole-block paste never reaches this. Line-by-line start refused: demo not installed. |
| `open "$run/summary.txt"` | macOS `open`. Line 5 looks at `$HOME/Library/Application Support/elastos-demo-a14`. That path is absent here, so the `&&` chain stops before `open`. On this Linux, `open` is xdg-open. |
| A14 itself | Needs the Mac install and the journeys. |

## Planted failure: `A14: PASS.` cannot be faked

F-A14ao (skip `write_summary` on the PASS path) was applied in the fresh clone only, then restored. Bytes matched afterwards (`demo.py` SHA-256 `a38b6460206ec5f14fd160a07f92b52a1acd3e34a2f44c4b2d6f5c6db7857574`).

| Check | Result |
| --- | --- |
| Control: `test_pass_writes_a14_pass_in_this_runs_summary` | PASS (1 test, 0.007 s) |
| After F-A14ao | FAIL at `summary.txt missing at .../summary.txt`. The PASS path still returns success, but this-run has no `summary.txt`. |
| Restore | SHA-256 match |
| FAIL journey (changed did-provider executable) | `exit 1`, `stdout_has_PASS False`, `summary_has_PASS False`, `summary_has_FAIL True` |

Line-by-line we also started `install.sh` and `run.sh` after preflight. Each wrote its own `summary.txt` under XDG (`evidence/`). Neither file contains `A14: PASS.`. Install wrote no `signing/` folder. Line 5 still looked at the Library path, so it did not open those files.

## One-time list

| Id | Line | Exit | Seconds | Class | Notes |
| --- | --- | --- | --- | --- | --- |
| onetime-mac-disk | A Mac with at least 40 GB of free disk space. | — | 0 | NOT RUN | 244.8 GiB free on this volume. |
| onetime-terminal | The Terminal app (Applications, then Utilities). | — | 0 | NOT RUN | macOS-only. |
| onetime-xcode-select | `xcode-select --install` | 127 | 0.000 | NOT RUN | No `xcode-select`. |
| onetime-rustup-rs | Go to rustup.rs and run the one command it shows. | 0 | 0.059 | AMBIGUOUS | `rustup 1.29.2` already on PATH. Installer not re-run. |
| onetime-rustup-1 | `rustup toolchain install 1.91.0` | 0 | 0.200 | PASS | `1.91.0-x86_64-unknown-linux-gnu unchanged`. |
| onetime-rustup-2 | `rustup target add wasm32-unknown-unknown --toolchain 1.91.0` | 0 | 1.689 | PASS | Downloaded `rust-std`. Sysroot then had `lib/rustlib/wasm32-unknown-unknown`. |
| onetime-fresh-clone-prose | Brand-new clone made by the morning block. | — | 0 | AMBIGUOUS | Instruction, not a command. |

## Morning fence, unit by unit

Comments and blanks are listed so every physical line has a row. Command units keep `if`/`fi` together. That is how a whole-block paste runs them. Pasting those `if` lines one at a time would show a `>` prompt.

| Id | Line | Exit | Seconds | Class | Notes |
| --- | --- | --- | --- | --- | --- |
| morning-01 | `set -euo pipefail` | 0 | 0.001 | PASS | A real paste keeps this on. |
| morning-02 | (blank) | 0 | 0 | PASS | No command. |
| morning-03 | `# 1. Brand-new folder...` | 0 | 0 | PASS | Comment. |
| morning-04 | `branch=cursor/demo-a14-installed-demo-83e1` | 0 | 0.000 | PASS | |
| morning-05 | `# This repository is private...` | 0 | 0 | PASS | Comment. |
| morning-06 | `#   A14_REMOTE=git@github.com:...` | 0 | 0 | PASS | Comment. |
| morning-07 | `url=${A14_REMOTE:-https://github.com/...}` | 0 | 0.000 | PASS | Default HTTPS URL. |
| morning-08 | `dest=${A14_CLONE:-"$HOME/a14-run-$(date +%Y%m%d-%H%M%S)"}` | 0 | 0.001 | PASS | Became `/home/ubuntu/a14-run-20261026-232441`. Same form works in bash `--posix` and zsh. |
| morning-09 | `if [ -e "$dest" ]; then ... exit 3; fi` | 0 | 0.000 | PASS | Dest was new. |
| morning-10 | `git clone --branch "$branch" "$url" "$dest"` | 0 | 2.885 | PASS | HEAD `3bff62b9`. |
| morning-11 | `cd "$dest"` | 0 | 0.000 | PASS | |
| morning-12 | `test -f lab/demo-a14/install.sh` | 0 | 0.000 | PASS | File present. |
| morning-13 | `if [ -n "$(git status --porcelain=v1)" ]; then ... fi` | 0 | 0.159 | PASS | Clean tree. |
| morning-14 | (blank) | 0 | 0 | PASS | |
| morning-15 | `# 2. Read-only check...` | 0 | 0 | PASS | Comment. |
| morning-16 | `sh lab/demo-a14/preflight.sh` | 1 | 0.227 | FAIL | Expected Linux stop. Whole-block paste ends here. |
| morning-17 | (blank) | 0 | 0 | PASS | |
| morning-18 | `# 3. Install and sign...` | 0 | 0 | PASS | Comment. |
| morning-19 | `bash lab/demo-a14/install.sh --sign` | 3 | 0.414 | NOT RUN | Started only because the recorder kept going. Refused the same four gaps. No key. |
| morning-20 | (blank) | 0 | 0 | PASS | |
| morning-21 | `# 4. Run every step...` | 0 | 0 | PASS | Comment. |
| morning-22 | `bash lab/demo-a14/run.sh` | 3 | 0.206 | NOT RUN | Started only by the recorder. "demo is not installed". No `A14: PASS.` |
| morning-23 | (blank) | 0 | 0 | PASS | |
| morning-24 | `# 5. Open only this run's summary.txt...` | 0 | 0 | PASS | Comment. |
| morning-25 | `demo_home="$HOME/Library/Application Support/elastos-demo-a14"` | 0 | 0.000 | PASS | Mac path, as written. |
| morning-26 | `run=$(sed -n '1p' "$demo_home/this-run" 2>/dev/null \|\| true)` | 0 | 0.002 | PASS | File missing; `run` empty. |
| morning-27 | `test -n "$run" && ... && open "$run/summary.txt"` | 1 | 0.000 | NOT RUN | Empty `run`, so `open` did not start. |

### Preflight output (morning-16)

```text
missing: operating system is Linux; A14's VERSIONS.json is produced on macOS
missing: architecture is x86_64; A14 needs native Apple Silicon (arm64)
missing: /usr/bin/sandbox-exec is missing; the C1-C7 steps run provider profiles with this macOS program
missing: /usr/sbin/lsof is missing; the conformance run checks earlier homes with this path
preflight: FAIL
```

After the one-time rustup lines there was no `missing: Rust toolchain 1.91.0` and no `missing: wasm32-unknown-unknown`. `/usr/bin/shasum` is present here. `crates.io` answered within the 2-second check.

## Whole-block confirmations

The exact second fence was run as one script, once with `bash --noprofile --norc`, once with `zsh --no-rcs`. Both cloned a new `$HOME/a14-run-<time>` at `3bff62b9`, printed the same four `missing:` lines, printed `preflight: FAIL`, exited 1, and left `this-run` pointing at the earlier line-by-line run. `install.sh` did not start.

Default macOS Terminal is zsh. The fence is labeled bash. On this Linux, zsh 5.9 accepted the block.

## What this does not prove

- Native arm64, Rosetta, Xcode CLT, quarantine on a browser zip, a real 40 GB disk refusal, `sandbox-exec`, macOS `/usr/sbin/lsof`, or the 30-minute install.
- GitHub password prompt on a Mac with no stored login.
- A14.

## Next

On the Mac: do the one-time list (skip rustup.rs if `rustup --version` already works), then paste the block. Book A14 only if that run's `summary.txt` ends with `A14: PASS.`

If you want the two AMBIGUOUS lines clearer first, apply `PROPOSED-RUNBOOK-PATCH.diff` on #289. It changes only the one-time prose. The morning fence is unchanged.
