# A2 Mac runbook

One paste so Sash can book A2 (resume after restart) on his Mac the
same way A14 has a one-paste morning block.

This folder is new. It does not edit `lab/a2-e2e-resume/`, other lab
lanes, BACKLOG.md, lane.env, or any 0.8.0 runtime code.

## Paste block

The only ` ```bash ` fence in [RUNBOOK.md](RUNBOOK.md):

- sha256: 3e9370470e3efcf776f300913566f10264a501d72e329fb3500dba57c8be50d2
- bytes: 24487

Those numbers are of the fence body, including its trailing newline,
and not of the markdown fences.

## Linux dry-run

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

The recorder pastes that exact block under zsh with a macOS `uname`
and `xcode-select` shim. It does not rebuild the real guest. It
proves the 18 earlier cases plus the r3 freeze, hash, lsof, and
waiter plants:

| Case | Last line | Plant |
| --- | --- | --- |
| happy path | `A2: PASS.` | six computed PASS rows; clone is a descendant of `9e7a85d6` |
| planted failing row | `A2: FAIL.` | `STALE: FAIL` |
| missing tool | `A2: NOT RUN.` | `rustup` hidden |
| tampered guest hash | `A2: FAIL.` | last wasm byte flipped after the pin |
| missing row | `A2: NOT RUN.` | `WRITE2` row missing; `A2_counted: yes` |
| duplicate WRITE | `A2: FAIL.` | two `WRITE: PASS` lines |
| survived falsifier | `A2: FAIL.` | `F-REV-GUEST-HASH SURVIVED` and exit 0 |
| late evidence rewrite | `A2: FAIL.` | `run.sh` backgrounds an 8s rewrite to FAIL |
| missing A2 pin | `A2: NOT RUN.` | clone has the lab files but no `9e7a85d6` |
| created `~/.elastos` | `A2: FAIL.` | `run.sh` creates `$HOME/.elastos` |
| `run.sh` exit 1 | `A2: FAIL.` | all-PASS evidence and nonzero journey |
| PASS then FAIL | `A2: FAIL.` | same row `PASS` then `FAIL` |
| `setsid` rewrite | `A2: FAIL.` | `setsid` daemon sleeps 12s, then writes FAIL |
| Python double-fork | `A2: FAIL.` | `os.setsid` plus double fork, then writes FAIL |
| evidence symlink | `A2: FAIL.` | `evidence.txt` is a symlink outside the clone |
| lookalike row | `A2: FAIL.` | `WRΙTE: FAIL` (Greek iota) plus a real `WRITE: PASS` |
| `HOME` redirect | `A2: FAIL.` | dummy `HOME`; `run.sh` creates the login-home `~/.elastos` |
| existing `~/.elastos` write | `A2: FAIL.` | `run.sh` writes into a pre-existing `~/.elastos` |
| `exec -a mds` + setsid at 22s | `A2: PASS.` | helper lives under `/tmp`, writes FAIL at 22s; freeze keeps evidence PASS |
| reopened fd at 22s | `A2: PASS.` | close, sleep 22s, reopen and write; freeze keeps evidence PASS |
| hardlink rewrite at 22s | `A2: PASS.` | rewrite via the other name at 22s; `uchg` on the inode blocks it |
| summary rewrite after score | `A2: FAIL.` | FAIL journey; helper rewrites `summary.txt` to PASS; file stays FAIL |
| same-size `~/.elastos` overwrite | `A2: FAIL.` | content becomes `plante\n` and mtime is restored; sha256 moves |
| read-only `mds` fd | `A2: PASS.` | `exec -a mds` holds a read-only fd on `evidence.txt` |
| unrelated argv | `A2: PASS.` | another process names `lab/a2-e2e-resume`; waiter uses absolute paths |
| `A2_CLEAN=1` after `uchg` | `A2: PASS.` | cleanup runs `chflags nouchg` inside the workdir, then removes it |

Recorded on this Linux x86_64 host, zsh 5.9, with the macOS shim.
A2 on macOS is **NOT RUN ON MAC** until Sash pastes the block on
Apple Silicon and that run's `summary.txt` ends with `A2: PASS.`

| Case | Last line | Plant | Result |
| --- | --- | --- | --- |
| happy path | `A2: PASS.` | six computed PASS rows; descendant of `9e7a85d6` | CAUGHT |
| planted failing row | `A2: FAIL.` | `STALE: FAIL` | CAUGHT |
| missing tool | `A2: NOT RUN.` | rustup hidden | CAUGHT (`missing: rustup is not on PATH`; rustc and cargo sit in the same rustup bin dir, so they were named too) |
| tampered guest hash | `A2: FAIL.` | last wasm byte flipped after the pin | CAUGHT |
| missing row | `A2: NOT RUN.` | `WRITE2` missing; `A2_counted: yes` | CAUGHT |
| duplicate WRITE | `A2: FAIL.` | two `WRITE: PASS` lines | CAUGHT |
| survived falsifier | `A2: FAIL.` | `F-REV-GUEST-HASH SURVIVED` and exit 0 | CAUGHT |
| late evidence rewrite | `A2: FAIL.` | background 8s rewrite to FAIL | CAUGHT |
| missing A2 pin | `A2: NOT RUN.` | no `9e7a85d6` object | CAUGHT |
| created `~/.elastos` | `A2: FAIL.` | `run.sh` creates `$HOME/.elastos` | CAUGHT |
| `run.sh` exit 1 | `A2: FAIL.` | all-PASS evidence and exit 1 | CAUGHT |
| PASS then FAIL | `A2: FAIL.` | same row `PASS` then `FAIL` | CAUGHT |
| `setsid` rewrite | `A2: FAIL.` | `setsid` daemon sleeps 12s, then writes FAIL | CAUGHT |
| Python double-fork | `A2: FAIL.` | `os.setsid` plus double fork, then writes FAIL | CAUGHT |
| evidence symlink | `A2: FAIL.` | `evidence.txt` is a symlink outside the clone | CAUGHT |
| lookalike row | `A2: FAIL.` | `WRΙTE: FAIL` (Greek iota) plus a real `WRITE: PASS` | CAUGHT |
| `HOME` redirect | `A2: FAIL.` | dummy `HOME`; login-home `~/.elastos` created | CAUGHT |
| existing `~/.elastos` write | `A2: FAIL.` | write into a pre-existing `~/.elastos` | CAUGHT |
| `exec -a mds` + setsid at 22s | `A2: PASS.` | `/tmp` helper writes FAIL at 22s | CAUGHT |
| reopened fd at 22s | `A2: PASS.` | reopen and write at 22s | CAUGHT |
| hardlink rewrite at 22s | `A2: PASS.` | rewrite via the other name at 22s | CAUGHT |
| summary rewrite after score | `A2: FAIL.` | helper rewrites `summary.txt` to PASS | CAUGHT |
| same-size `~/.elastos` overwrite | `A2: FAIL.` | `plante\n` with restored mtime | CAUGHT |
| read-only `mds` fd | `A2: PASS.` | read-only Spotlight-named fd on `evidence.txt` | CAUGHT |
| unrelated argv | `A2: PASS.` | argv contains `lab/a2-e2e-resume` | CAUGHT |
| `A2_CLEAN=1` after `uchg` | `A2: PASS.` | `nouchg` then `rm -rf` of the workdir | CAUGHT |

## Before Sash pastes

- Native Apple Silicon Terminal. Rosetta is a named NOT RUN.
- `xcode-select --install` already done in another window. The paste
  never runs it and never uses `sudo`.
- `rustup --version` already works. The paste skips
  `toolchain install` / `target add` when 1.91.0 and
  `wasm32-unknown-unknown` are present. It never curls rustup.rs.
- Do not clone first. The paste uses `mktemp` and a trap.
- About 20 GiB free on the `/tmp` volume. First real run compiles the
  guest and `a2-resume-driver`, then `run.sh` (journey plus
  falsifiers). Keep the Mac awake.
- Sign in to GitHub the usual way. If `git clone` asks for a
  password, Ctrl-C and paste again with
  `A2_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`.
- The paste never runs `elastos serve`, never writes Sash's real
  Home, and refuses if it creates or changes `~/.elastos` under
  `$HOME` or the login home. The new guest pin is written only
  inside the temp clone. The Linux pin from #351 will not match a
  Mac rebuild; that is expected. Do not copy the new pin into a
  committed file unless you mean to re-pin for Mac.

Book A2 only on `A2: PASS.` from that Mac `summary.txt`.
