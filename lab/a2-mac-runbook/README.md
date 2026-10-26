# A2 Mac runbook

One paste so Sash can book A2 (resume after restart) on his Mac the
same way A14 has a one-paste morning block.

This folder is new. It does not edit `lab/a2-e2e-resume/`, other lab
lanes, BACKLOG.md, lane.env, or any 0.8.0 runtime code.

## Paste block

The only ` ```bash ` fence in [RUNBOOK.md](RUNBOOK.md):

- sha256: 409684d41a3c97f476085a05e61fca5c571583c8e41f86a8147013f4bf9d41eb
- bytes: 11683

Those numbers are of the fence body, including its trailing newline,
and not of the markdown fences.

## Linux dry-run

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

The recorder pastes that exact block under zsh with a macOS `uname`
and `xcode-select` shim. It does not rebuild the real guest. It
proves:

| Case | Last line | Plant |
| --- | --- | --- |
| happy path | `A2: PASS.` | six computed PASS rows |
| planted failing row | `A2: FAIL.` | `STALE: FAIL` |
| missing tool | `A2: NOT RUN.` | `rustup` hidden |
| tampered guest hash | `A2: FAIL.` | last wasm byte flipped after the pin |

Recorded on this Linux x86_64 host, zsh 5.9, with the macOS shim.
A2 on macOS is **NOT RUN ON MAC** until Sash pastes the block on
Apple Silicon and that run's `summary.txt` ends with `A2: PASS.`

| Case | Last line | Plant | Result |
| --- | --- | --- | --- |
| happy path | `A2: PASS.` | six computed PASS rows | CAUGHT |
| planted failing row | `A2: FAIL.` | `STALE: FAIL` | CAUGHT |
| missing tool | `A2: NOT RUN.` | rustup hidden | CAUGHT (`missing: rustup is not on PATH`; rustc and cargo sit in the same rustup bin dir, so they were named too) |
| tampered guest hash | `A2: FAIL.` | last wasm byte flipped after the pin | CAUGHT |

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
  Home, and refuses if it creates `~/.elastos`. The new guest pin is
  written only inside the temp clone. The Linux pin from #351 will
  not match a Mac rebuild; that is expected. Do not copy the new pin
  into a committed file unless you mean to re-pin for Mac.

Book A2 only on `A2: PASS.` from that Mac `summary.txt`.
