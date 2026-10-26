# A14 installed demo

M1 check A14 says: Sash runs the installed demo, and its versions are bound.

This folder gives you two commands. `install.sh` installs the demo once. `run.sh`
runs it. The run shows each agent journey, one step at a time, and says if the
step passed or was refused, and why. Before it runs anything, it compares every
installed part with one receipt file, `VERSIONS.json`. If one part is different,
the demo stops and runs nothing.

## What you need, one time

- A Mac with at least 40 GB of free disk space.
- The Terminal app (in Applications, then Utilities).
- Apple's command line tools. In Terminal, type `xcode-select --install` and
  follow the window. If it says they are already installed, that is fine.
- Rust. Go to <https://rustup.rs> and run the one command it shows. Then close
  Terminal and open it again.
- A copy of this repository on your Mac.

## Step 1: open the repository folder

In Terminal, go to the folder where your copy of the repository is. For example:

```bash
cd ~/code/elastos-agent-host-spike
```

The first time only, add the Rust target the demo builds for:

```bash
rustup target add wasm32-unknown-unknown
```

## Step 2: get the version to test

```bash
git checkout spike/agent-host
git pull --ff-only
git status
```

The last command must say `nothing to commit, working tree clean`. If it says
something else, stop and ask an engineer. The demo refuses to install from a
copy with local changes.

## Step 3: install

```bash
bash lab/demo-a14/install.sh
```

The install does five things and prints each one:

1. It downloads the Rust packages that the builds need. This needs the internet.
2. It runs the full agent conformance check (`lab/agent-conformance/run.sh`).
   That check writes a new `VERSIONS.json`, which records the exact Runtime,
   provider and test capsules it used.
3. It builds the agent-host guest from the same version of the code.
4. It builds the journey tests, so that the run does not have to.
5. It copies the Runtime, the provider, the guest and `VERSIONS.json` into
   `~/Library/Application Support/elastos-demo-a14/current`.

The first install can take 30 minutes or more. Keep the Mac awake and plugged
in, and do not start other builds at the same time.

A good install ends like this:

```text
Installed. VERSIONS.json SHA-256 <64 letters and digits>.
Receipt: <path to VERSIONS.json>
Next: bash lab/demo-a14/run.sh
```

If you see `REFUSED:`, read the lines under it. Each line names one problem.
The last line says what to do next.

## Step 4: run

```bash
bash lab/demo-a14/run.sh
```

First the run checks the versions and prints them. Then it runs each step and
prints a block like this:

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

- `A14: PASS.` Every step ran, and every step used the versions in `VERSIONS.json`.
- `A14: NOT RUN.` Some steps did not run here. A14 is not done.
- `A14: FAIL.` A step failed, or the versions changed during the run. A14 is not done.

The `Saved:` line names a folder. It holds `summary.txt` (the same text you see)
and the full output of each test group.

## When the run says the versions do not match

```text
REFUSED: the installed versions do not match VERSIONS.json. No journey was run.
```

This is the version lock. Something changed after the install: new code, a
rebuilt file or a changed copy. Each line under the message names the part and
both fingerprints. Run `bash lab/demo-a14/install.sh` again, then run again.

## See the lock work (optional)

This changes one byte of the installed Runtime copy, shows the refusal, and then
puts the right copy back. Use the receipt path that your install printed.

```bash
printf x >> ~/Library/Application\ Support/elastos-demo-a14/current/bin/elastos
bash lab/demo-a14/run.sh
bash lab/demo-a14/install.sh --receipt "<the Receipt path from Step 3>"
```

The run must print `REFUSED`, name `installed elastos`, and run no step. The
second install is quick because it reuses the receipt and the builds.

## What to send back

Send the `summary.txt` file from the `Saved:` folder, or copy everything the run
printed.

## Clean up

When the result is reviewed, delete the folder
`~/Library/Application Support/elastos-demo-a14`. It holds only the demo's
copies and run outputs.

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
- Its bytes still match the SHA-256 that the install recorded.
- The installed `elastos` and `localhost-provider` match its `runtime_sha256` and
  `localhost_provider_sha256`, and so do the copies in
  `lab/agent-conformance/target/runtime/debug` that the A8 journey launches.
- This checkout is at the receipt's commit and has no local changes.
- The agent-host guest that A1 and A2 load matches the copy pinned at install.

After the steps, every `version identity:` line a journey printed must match
the receipt. The A8 journey must print the Runtime, the provider and its
`host-key-read` probe. The run then checks all of the above again.

**What this does not prove.**

- `VERSIONS.json` is not signed. The lock proves that the run used the same bytes
  as the receipt, not who wrote the receipt.
- The A1, A2 and C steps run Runtime crates and providers that Cargo builds from
  the receipt's commit. `VERSIONS.json` does not hash those builds; the commit
  and the clean checkout bind them.
- The A8 journey launches the byte-identical copy in the lab build folder, not
  the installed copy itself.
- The C steps start each provider under its own profile with `sandbox-exec`.
  The Runtime does not generate or apply that profile yet (M1 check B3).
- Off macOS, every macOS step prints NOT RUN, and the demo never prints
  `A14: PASS`.

**Checks for this folder.**

```bash
python3 -I -m unittest discover -s lab/demo-a14/tests -v
```

`falsifiers.json` lists 14 planted bugs, each with the tests that must fail.
The shared falsifier runner has no command for this folder, so apply each edit
by hand, require its tests to fail, restore the bytes, and require them to pass.
