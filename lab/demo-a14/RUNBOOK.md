# A14 installed demo

## What you need, one time

Do this list first. The paste below does not add these tools.

- A Mac with at least 40 GB of free disk space.
- The Terminal app (in Applications, then Utilities).
- Apple's command line tools. In Terminal, type `xcode-select --install` and
  follow the window. If it says they are already installed, that is fine. They
  include `git`, `python3` and `ssh-keygen`, which signs the receipts.
- Rust. If `rustup --version` already works, skip this. Otherwise go to
  <https://rustup.rs> and run the install command shown on that page. Then close
  Terminal and open it again.
- The Rust pin and wasm target the demo builds for. These two commands install
  the pin in `rust-toolchain.toml` and put the wasm target on that pin. The
  paste does not do this.

```bash
rustup toolchain install 1.91.0
rustup target add wasm32-unknown-unknown --toolchain 1.91.0
```

- Do not clone first. The morning block itself creates a fresh
  `$HOME/a14-run-<time>` clone (`git clone --branch`). Do not run `git checkout`
  in a tree you already have. A zip from a browser can make macOS refuse to run
  the built programs. Preflight reports `com.apple.quarantine` and does not
  strip it.

## Sash's morning steps

Paste this whole block. It is one script. A failed line stops the rest.
It clones into a **new** folder. It never runs `git checkout` in an existing
tree. Leave `/Users/sash/code/wt-agent-host` and
`~/code/elastos-agent-host-spike` as they are.

Sign in to GitHub the way you usually do. The block uses
`A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git` (SSH key).

```bash
set -euo pipefail

# 1. Brand-new folder. Refuse if that path already exists. Stop if install.sh is missing.
branch=cursor/demo-a14-installed-demo-83e1
# This repository is private. If git asks for a password, Ctrl-C and rerun with:
#   A14_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git
url=${A14_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
dest=${A14_CLONE:-"$HOME/a14-run-$(date +%Y%m%d-%H%M%S)"}
if [ -e "$dest" ]; then
  printf 'REFUSED: %s already exists. This runbook never reuses a folder.\n' "$dest" >&2
  exit 3
fi
git clone --branch "$branch" "$url" "$dest"
cd "$dest"
test -f lab/demo-a14/install.sh
if [ -n "$(git status --porcelain=v1)" ]; then
  printf 'REFUSED: the new clone has local changes. Stop and ask an engineer.\n' >&2
  exit 3
fi

# 2. Read-only check of this Mac. Stop on "preflight: FAIL".
sh lab/demo-a14/preflight.sh

# 3. Install and sign (30 minutes or more the first time)
bash lab/demo-a14/install.sh --sign

# 4. Run every step against the installed versions
bash lab/demo-a14/run.sh

# 5. Open only this run's summary.txt. Book A14 only on "A14: PASS."
demo_home="$HOME/Library/Application Support/elastos-demo-a14"
run=$(sed -n '1p' "$demo_home/this-run" 2>/dev/null || true)
test -n "$run" && test -d "$run" && test -f "$run/summary.txt" && open "$run/summary.txt"
```

Until this demo is on `spike/agent-host`, the new clone stays on
`cursor/demo-a14-installed-demo-83e1`. That branch is the one that contains
`lab/demo-a14`. `spike/agent-host` does not have these files yet.

The rest of this file explains each line, and what to do if a line says
`REFUSED`.

## What this is

M1 check A14 says: Sash runs the installed demo, and its versions are bound.

This folder gives you two commands. `install.sh` installs the demo once. `run.sh`
runs it. The run shows each agent journey, one step at a time, and says if the
step passed or was refused, and why. Before it runs anything, it compares every
installed part with two receipt files: `VERSIONS.json`, which the conformance
check writes, and `INSTALL.json`, which the install writes. If one part is
different, the demo stops and runs nothing.

## Lines 1 and 2: the version to test

Line 1 makes a brand-new folder named `$HOME/a14-run-<timestamp>` (or
`$A14_CLONE` if you set it). It refuses if that path already exists. It never
changes `/Users/sash/code/wt-agent-host` or `~/code/elastos-agent-host-spike`.
After the clone, `lab/demo-a14/install.sh` must be present and
`git status --porcelain=v1` must print nothing. If either check fails, the
script stops.

Line 2 is `preflight.sh`. It writes nothing. It names each gap on its own
`missing:` line, then prints `preflight: OK` or `preflight: FAIL`. Stop on
FAIL. `install.sh` runs that same script again before any download or signing
key, so skipping line 2 cannot start the long run.

## Line 3: install

The install first runs the same `preflight.sh` as line 2. A failure prints
`REFUSED: this machine is not ready.`, writes this run's `summary.txt`, and
writes no signing key. Then it does five things and prints each one:

1. It downloads the Rust packages that the builds need. This needs the internet.
2. It runs the full agent conformance check (`lab/agent-conformance/run.sh`).
   That check writes a new `VERSIONS.json`, which records the exact Runtime,
   provider and test capsules it used.
3. It builds the agent-host guest from the same version of the code.
4. It builds the journey tests and records the fingerprint (SHA-256) of every
   test program and provider program that the run will start.
5. It copies the Runtime, the provider, the guest and `VERSIONS.json` into
   `~/Library/Application Support/elastos-demo-a14/current`, and writes
   `INSTALL.json` with every fingerprint.

With `--sign`, the install makes the signing key only when the builds have
finished and it is about to write the receipts (see "The signature" below). A
failed conformance run or a missing `VERSIONS.json` leaves no new key. If the
install write then fails, it removes only the key this run created and says
so. Keep the Mac awake and plugged in, and do not start other builds at the
same time.

A good install ends like this:

```text
Installed. VERSIONS.json SHA-256 <64 letters and digits>.
Receipt: <path to VERSIONS.json>
Next: bash lab/demo-a14/run.sh
```

If you see `REFUSED:`, read the lines under it. Each line names one problem.
The last line says what to do next.

## Line 4: run

First the run checks the versions and prints them, the program fingerprints and
the signature. Then it runs each step and prints a block like this:

```text
  A8         REFUSED  A capsule cannot read a host SSH key
                      reason: Internal("capsule manifest does not declare authority for ...")
                      test: host_key_read_is_refused
```

The second word tells you what happened:

| Word | Meaning |
| --- | --- |
| PASS | The allowed action worked. |
| REFUSED | The system said no, as it must. This is a good result. |
| FAIL | The step did not behave as it should. Send the output to an engineer. |
| NOT RUN | The step could not run on this machine. It does not count as a pass. |

At the end, a summary gives one line for each M1 check, then one final line:

- `A14: PASS.` Every step ran, and every step used the versions in the receipts.
- `A14: NOT RUN.` Some steps did not run here. A14 is not done.
- `A14: FAIL.` A step failed, or the versions changed during the run. A14 is not done.

## Line 5: what to send

Line 5 opens only this run's `summary.txt` (the path in `this-run`). It does
not pick the newest folder by date. Every install refusal and every run writes
that file and points `this-run` at it. The `Next:` line names the same path.
Send that file. Book A14 only when it ends with `A14: PASS.`
The folder also holds the full output of each test group when journeys ran.

## When the run says the versions do not match

```text
REFUSED: the installed versions do not match VERSIONS.json. No journey was run.
```

This is the version lock. Something changed after the install: new code, a
rebuilt program, a changed copy, or a changed receipt. Each line under the
message names the part and both fingerprints. Run line 3 again, then line 4.

## The signature

`install.sh --sign` makes one ed25519 key for this Mac with `ssh-keygen` and
keeps it in `~/Library/Application Support/elastos-demo-a14/signing`. The key
never goes into the repository. The install signs `VERSIONS.json` and
`INSTALL.json` with it.

While that key exists, signing is on. Then the run refuses to start if either
receipt file has no signature, or if a signature does not match the file and this
Mac's key.

The signature proves that the receipts are unchanged since the install on this
Mac. It does not prove who published them, because the key was made here and
nobody else trusts it.

To turn signing off, delete the `signing` folder, then install again without
`--sign`.

## See the lock work (optional)

This changes one byte of the installed Runtime copy, shows the refusal, and then
puts the right copy back. Use the receipt path that your install printed.

```bash
printf x >> ~/Library/Application\ Support/elastos-demo-a14/current/bin/elastos
bash lab/demo-a14/run.sh
bash lab/demo-a14/install.sh --receipt "<the Receipt path from line 3>"
```

The run must print `REFUSED`, name `installed elastos`, and run no step. The
second install is quick because it reuses the receipt and the builds.

To see the signature work, add one space to the end of the installed
`VERSIONS.json`, run, and look for `VERSIONS.json signature does not verify`.
Then install again with `--receipt` as above.

## Clean up

When the result is reviewed, delete the folder
`~/Library/Application Support/elastos-demo-a14`. It holds the demo's copies,
run outputs and, if you used `--sign`, this Mac's demo key.

## For the reviewer

**What each check means here.** The M1 sheet is not in this repository, so the
list of which test stands for which M1 check is this demo's reading. Sash
confirms it before A14 is booked. `journeys.json` names the exact test for every
step; the run prints each one.

| Check | Steps in the run |
| --- | --- |
| A1 WASM admission | The Runtime's Wasmtime admits the real agent-host component; it refuses a component with an import outside the Bus, and an unsigned or untrusted capsule. |
| A2 journal | With both grants the agent host writes and reads its journal through the real bridge; with both denied it stores nothing; an old journal format is refused with its reason. |
| A8 host-secret refusal | The real `elastos` binary refuses a capsule's read of a fake host SSH key. |
| C1 to C7 provider refusals | The did, wallet and model providers under their `confine.sb`: outside read, outside write, a file beside the root, another program, network, a profile that cannot be applied, and a refused start that names its reason. |

**What binds the versions.** Before any step, the run requires all of these. A
difference is a refusal with exit code 3, and no step runs.

- `VERSIONS.json` comes from `lab/agent-conformance` (schema
  `agent-conformance.versions/v1`), is complete, records a passing command, a
  clean commit and its own `versions_receipt (A14) | PASS` row.
- Its bytes still match the SHA-256 that `INSTALL.json` recorded.
- The installed `elastos` and `localhost-provider` match its `runtime_sha256` and
  `localhost_provider_sha256`, and so do the copies in
  `lab/agent-conformance/target/runtime/debug` that the A8 journey launches.
- The agent-host guest that A1 and A2 load matches its SHA-256 in `INSTALL.json`.
- Each suite's test executable, and each provider binary the C tests start,
  matches its SHA-256 in `INSTALL.json` and lies inside the repository. The
  install takes these from Cargo's own artifact report, and refuses a suite with
  no test executable or more than one.
- The checkout is at the receipt's commit and has no local changes.
- With signing on, both receipt files carry a valid signature by this Mac's key.

**How each step runs.** A1, A2 and the C steps run their recorded test
executable directly, never through Cargo, so nothing can be rebuilt between the
check and the run. Each suite's files are checked again immediately before and
after it runs. A suite whose files changed is refused before it runs.

A8 runs through `cargo test` with the same environment as
`lab/agent-conformance/run.sh`. Its harness builds `elastos` with Cargo inside
the test, and that build starts again under any other parent. On Linux, the
same build under `cargo test`'s environment recompiled from `ring` up in 2m41s,
although the binary came out byte-identical. Cargo must report that it ran
exactly the recorded A8 test executable. Immediately before and after A8, the
`elastos` and `localhost-provider` that A8 launches must be byte-identical to the
installed copies; otherwise A8 is refused before it runs. The harness launches
its own build path, so the run proves identity with the installed copy rather
than starting the installed path itself.

After the steps, every `version identity:` line a journey printed must match the
receipt. The A8 journey must print the Runtime, the provider and its
`host-key-read` probe. The run then checks everything above again.

**What this does not prove.**

- The signature proves integrity on this Mac, not publisher identity. Without
  `--sign`, nothing is signed, and the lock proves only that the bytes match the
  receipts.
- `VERSIONS.json` hashes no agent-host guest or test executable. Those hashes are
  in `INSTALL.json`, which the install writes after the conformance run.
- The A8 harness starts `elastos` from its own build folder. The run proves that
  file is byte-identical to the installed copy before and after A8, but it does
  not start the installed path.
- The C steps start each provider under its own profile with `sandbox-exec`.
  The Runtime does not generate or apply that profile yet (M1 check B3).
- Off macOS, every macOS step prints NOT RUN, and the demo never prints
  `A14: PASS`.

**Checks for this folder.**

```bash
python3 -B -I -m unittest discover -s lab/demo-a14/tests -v
```

The signing tests need `ssh-keygen`. `falsifiers.json` lists planted bugs,
each with the tests that must fail. The shared falsifier runner has no command
for this folder, so apply each edit by hand, require its tests to fail, restore
the bytes, and require them to pass. Use `-B`: a same-size edit restored in the
same second can otherwise leave the planted bytecode in use. `falsify.sh`
plants a missing `ssh-keygen` against `preflight.sh`.
