# macOS review of install.sh and run.sh

Reviewed on the PR 289 commit `25d524e549439be0757cc672a1d39b0b8459dec2`. This VM is Linux, Bash 5.2.21, Python 3.12.3, OpenSSH 9.6p1. Bash 3.2 was not executed. `bash --posix -n` accepts both scripts.

Both scripts are four lines. They enable `set -euo pipefail` and replace the shell with:

```sh
exec python3 -I "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/demo.py" install "$@"
```

`run.sh` is the same call with `run`. The work is in `demo.py`, and step 2 of install starts `lab/agent-conformance/run.sh`. The notes below cover the wrappers and the commands they actually start.

## Tool differences

| Tool | In install.sh / run.sh | On macOS |
| --- | --- | --- |
| `sed -i` | Absent | Would be a different flag (`sed -i ''`). Not used. |
| `stat` | Absent | BSD `stat` and GNU `stat` differ. The scripts do not call `stat`. Modes are checked in Python with `os.stat` only in the unit tests. |
| `readlink -f` | Absent | macOS `readlink` has no `-f`. The wrappers use `pwd -P`, which is POSIX and resolves the script directory. |
| `date` | Absent | `demo.py` formats UTC with `time.strftime` and `time.gmtime`. The format is numeric, so the locale does not change it. |
| `sha256sum` | Absent | macOS has `shasum`, not `sha256sum`. The demo hashes with Python `hashlib`. The conformance run, which install starts on a Mac, calls `/usr/bin/shasum` from `lab/agent-conformance/src/runtime.rs`. That path exists on macOS. |
| `mktemp` | Absent in these two scripts | `demo.py` uses `tempfile.mkdtemp`. `lab/agent-conformance/run.sh` uses `mktemp -d "$lane/target/run-table.XXXXXX"`. That template form works with BSD `mktemp`. |

`set -o pipefail` has been in Bash since 3.0. The wrappers contain no pipe, so the option does not change their result. `BASH_SOURCE` and `"$@"` under `set -u` are valid on Bash 3.2. The shebang is `#!/usr/bin/env bash`. On a Mac that has only `/bin/bash`, that is Bash 3.2, and these two scripts stay inside what 3.2 implements.

A copy of the wrapper with a space in its directory (`/tmp/a14 space bin/install.sh`) ran `python3 -I` and printed the stub program's line. Exit 0. `ssh-keygen -f` with a key path containing a space created a mode `0600` file. The install directory on a Mac is `~/Library/Application Support/elastos-demo-a14`, which contains a space. `demo.py` passes that path as an argument list, not through a shell.

## What the wrappers do not decide

`python3 -I` is isolated mode. It ignores `PYTHONPATH` and the user site. The demo imports the standard library only. Preflight runs the same `python3 -I` and requires Python 3.9 or newer, which is the older interpreter the PR's own tests used.

`platform.system()` is `Darwin` on macOS. The script then uses `~/Library/Application Support/elastos-demo-a14`. On Linux it uses `$XDG_DATA_HOME` or `~/.local/share`. The dry run showed that split: the key landed in `~/.local/share/elastos-demo-a14`, and step 5 still looked under `~/Library`.

Hashes, the receipt, the git status check, and the signature are all in `demo.py`. They do not call `sha256sum`, `stat`, or `date`.

## Gatekeeper and quarantine

The morning install does not download a release binary. `cargo` compiles the Runtime, the providers, the guest, and the test executables. A git clone does not set `com.apple.quarantine` on those outputs.

`shutil.copy2` keeps extended attributes. If a browser zip of the repository carried the quarantine attribute onto a file that is later copied, the copy keeps it, and macOS can refuse to execute it. The scripts never clear that attribute. The runbook's step 2 is a git checkout, which is the path that avoids the attribute. Preflight reports the attribute when it is present and does not remove it.

An ad-hoc Mach-O signature lives in the file bytes. `copy2` copies those bytes. The install path's space does not, by itself, break that signature.

## Apple Silicon

Nothing in `install.sh`, `run.sh`, or `demo.py` reads the architecture.

`lab/agent-conformance/tests/common/mod.rs` accepts `darwin-arm64` and `darwin-amd64`. `components.json` lists `darwin-arm64` for `localhost-provider` and has no `darwin-amd64` row. The home writer inserts a platform row when it is absent, so an Intel build is not refused by that code.

A Terminal under Rosetta reports `x86_64` and `sysctl.proc_translated=1`. That shell builds x86_64 binaries and records those hashes. It is a different run from a native arm64 Terminal. Preflight treats a non-arm64 or translated shell as missing the machine A14 names. The installer does not.

## Paths with spaces

The wrappers quote the script path. `demo.py` and `ssh-keygen` receive paths as arguments. The Mac install directory is safe on that path.

The guest build is not. `install.sh` runs `examples/agent-host/build.sh`, which runs `scripts/build-component-capsule.sh`. That script puts `$HOME`, `$CARGO_HOME`, the repository path, and the rustc sysroot into `RUSTFLAGS`. rustc splits `RUSTFLAGS` on spaces. A space in any of those four paths breaks step 3. Sash's home in the handover is `/Users/sash`, which has no space. The failure shows up for a checkout or a Cargo home that has one.

`CARGO_TARGET_DIR`, when set to an absolute directory outside the repository, is inherited by the test builds. `demo.py` then refuses those executables as outside the checkout. That refusal is step 4, after the conformance run. The variable was unset in this dry run, so the refusal was not observed here. The code path is `suite_env`, which copies `os.environ`.

`CARGO_TERM_COLOR=always` can make Cargo color the `Running` line. `cargo_ran_problems` matches a plain `Running ... (path)` line. The captured pipe is not a terminal, so Cargo's default is plain text. The environment variable overrides that default. It was unset here.

## Bash 3.2 in the script install starts

`lab/agent-conformance/run.sh` is `#!/bin/bash` with `set -eu` and one array, `features`. The expansion is `${features[@]+"${features[@]}"}`, which is the Bash 3.2 form that survives `set -u` when the array is empty. Install invokes it as `bash run.sh`, so a Homebrew Bash on `PATH` is used when present, and `/bin/bash` otherwise. The script does not need Bash 4.

## Step 5 of the runbook

```sh
open "$(ls -dt ~/Library/Application\ Support/elastos-demo-a14/runs/*/ | head -1)"
```

The backslash keeps the space. That part worked on this VM: `ls` looked at the expanded Library path. `ls -dt` is the same flag pair on BSD and GNU. `head -1` works on both.

When the directory is missing, the glob stays literal, `ls` writes an error, the substitution is empty, and `open` is started with no argument. That is what step 5 did here. macOS `open` with no argument prints usage and does not reveal a refusal that was only printed in the terminal. A refusal before any journey does not write `summary.txt`. The dry run's `find` of the demo home showed the signing key and no `runs/` directory.
