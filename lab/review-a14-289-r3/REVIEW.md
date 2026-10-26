# Adversarial review r3 of PR 289 (A14 morning runbook)

Draft. Do not merge. A14 itself is **NOT RUN**. Only Sash's Mac run counts.
PR 289's branch was not edited, not pushed, and not commented on.

```text
Slice:        r3 independent review of PR 289 after the r2 RUNBOOK-only fix
Branch / PR:  cursor/review-a14-289-r3-3a54
Read:         https://github.com/Elacity/elastos-agent-host-spike/pull/289
Claimed head: 97c1b8836d930a29d5dbb43d5766658d4bf7c41c
Actual head:  97c1b8836d930a29d5dbb43d5766658d4bf7c41c   (matches)
Parent:       e6651b29becaca6db12065413169e2fafce6cd64
r2 review:    PR 377, lab/review-a14-289-r2/REVIEW.md against then-head e6651b29
Machine:      Linux x86_64, Python 3.12.3, zsh 5.9, bash 5.2.21,
              compiled bash 3.2.57 (same series as macOS /bin/bash)
```

Work is only under `lab/review-a14-289-r3/`. A detached worktree at `97c1b883` was used to read and run tests. PR 289 was left as-is.

**Verdict for handing Sash this block as his first paste: NO-GO.**

r2's two runbook holes are closed: the one-time list sits above the fence, and the SSH comment is the right remote. The fence is safe to paste in zsh 5.9, bash 3.2.57, and bash 5. Step 5 opens only this run's `summary.txt`. 76 unit tests passed. `falsify.sh` caught the ssh-keygen plant.

The first paste still dies at preflight on a Mac that only did the list as written. `rustup.rs` installs current stable. `rustup target add wasm32-unknown-unknown` (no `--toolchain`, and he has not cloned yet) adds that target to the default toolchain. Preflight then looks for `1.91.0-<triple>` with `wasm32-unknown-unknown` on that pin. The morning block does not install either.

## Head and the r2-to-r3 diff

`git diff --stat e6651b29..97c1b883` is one file: `lab/demo-a14/RUNBOOK.md` (24 insertions, 21 deletions). The PR body fence and the RUNBOOK fence are the same 1336 bytes. No CRLF. No smart quotes.

r2 asked for two edits. Both landed:

1. The "What you need, one time" list is now above the paste, and it includes `rustup target add wasm32-unknown-unknown`.
2. The two comment lines sit just above `url=`, naming the private repo and `A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`.

## One-time list vs what the scripts call

`preflight.sh` and `install.sh` (`demo.py install`) ask for these tools:

| Tool | Where it comes from | On the list? |
| --- | --- | --- |
| Xcode CLT / `xcode-select` | the list (`xcode-select --install`) | yes |
| `git`, `python3` (3.9+) | CLT | yes (named under CLT) |
| `ssh-keygen` (OpenSSH 8.1+, `-Y`) | macOS OpenSSH; the list attributes it to CLT | present either way |
| `rustup` | rustup.rs | yes |
| `wasm32-unknown-unknown` **on 1.91.0** | must be added to the pin | **no — listed add hits the default toolchain** |
| pinned `rustc`/`cargo` **1.91.0** | `rust-toolchain.toml`; preflight does not install it | **no** |
| `bash`, `curl`, `open`, `/usr/bin/shasum`, `/usr/bin/sandbox-exec`, `/usr/sbin/lsof` | stock macOS | no need to list |
| 40 GB free disk, native arm64 Terminal | the list / "A Mac" | yes |

`install.sh` is `python3 -I demo.py install`. It re-runs `preflight.sh`, then `cargo fetch` / the conformance run / the guest build / `ssh-keygen`. It does not call `node`, `just`, `rustfmt`, or `clippy`. Those stay off the list.

A fake rustup home proved the gap:

- Only `stable` plus wasm32 on `stable` → `missing: Rust toolchain 1.91.0 ... is not installed ...; preflight does not install it`
- `1.91.0` present, wasm32 only on `stable` → `missing: wasm32-unknown-unknown is not installed for 1.91.0; the guest build needs it, and the five morning steps do not add it`
- wasm32 under `1.91.0-<triple>` → those two lines go away

The live Linux paste of steps 1–2 on this head also printed the wasm32-for-1.91.0 line, then `preflight: FAIL`, exit 1.

## Fence copy-paste (zsh 5.9, bash 3.2.57, bash 5.2)

`set -euo pipefail` parses in all three. With `A14_REMOTE` and `A14_CLONE` unset, `url` is the HTTPS default and `dest` is `$HOME/a14-run-YYYYMMDD-HHMMSS`. Setting both overrides works. An empty `this-run` leaves step 5 quiet and the script continues.

A local-remote paste of steps 1–2 (so `install.sh` is never started) in each shell:

```text
clone HEAD: 97c1b8836d930a29d5dbb43d5766658d4bf7c41c
clone branch: cursor/demo-a14-installed-demo-83e1
install.sh present; porcelain empty
preflight: FAIL
exit: 1
this-run: absent; summary.txt count: 0
```

Reusing the same `A14_CLONE` is exit 3, "already exists".

## SSH remote comment

The default URL is HTTPS to this private repo. A Terminal with no helper asks for a password and the clone dies (r2 walk, exit 128, dest absent). The comment tells him to Ctrl-C and rerun with `A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`. That is the SSH form of `origin`. A shell assignment of that name persists, then the next paste uses it. A failed HTTPS clone leaves dest absent, so the timestamp dest can be used again.

## Step 5 opens only this run

The fence reads `$demo_home/this-run` and opens that folder's `summary.txt`. It does not use `ls -dt`. A planted pointer at an older run, with a newer sibling folder beside it, made `open` receive only the older `summary.txt` in all three shells. `install` and `run` both call `mark_this_run` before they return 0, so a fence that reaches step 5 has a current pointer.

## Tests re-run here (worktree at 97c1b883)

```text
python3 -B -I -m unittest discover -s lab/demo-a14/tests -v
  -> Ran 76 tests in 1.553s  OK
git diff --check
  -> clean
sh lab/demo-a14/falsify.sh
  -> falsifier: CAUGHT (ssh-keygen PATH plant, 0.071s)
```

## Exact edit

Change only the Rust bullets in `lab/demo-a14/RUNBOOK.md` (and the matching lines in the PR summary). Leave the fence, the SSH comment, and `set -euo pipefail` as they are.

Replace:

```bash
rustup target add wasm32-unknown-unknown
```

with:

```bash
rustup toolchain install 1.91.0
rustup target add wasm32-unknown-unknown --toolchain 1.91.0
```

Add one short line above that block: these two commands install the pin in `rust-toolchain.toml` and put the wasm target on that pin. The paste does not do this.

## NOT RUN (only a real Mac can prove)

- A14 itself (`A14: PASS.` from `run.sh` with `summary.txt` from that run)
- Native arm64 Terminal, Rosetta, `/usr/bin/sandbox-exec`, macOS `/usr/bin/shasum`, `/usr/sbin/lsof`, macOS `open`
- Stock macOS `/bin/bash` 3.2 and stock macOS zsh (this review used Linux zsh 5.9 and a compiled bash 3.2.57)
- HTTPS clone on a Mac that already has `gh auth` or a credential helper
- A 40 GB disk refusal on a Mac that is actually low on disk

## Next

Owner of PR 289 applies the two rustup lines. This review stays draft. Book A14 only when Sash's Mac prints `A14: PASS.` and `summary.txt` is from that run.
