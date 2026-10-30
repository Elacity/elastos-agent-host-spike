# Fixes for PR 289

For the owner of `cursor/demo-a14-installed-demo-83e1`. This file does not change that branch. A14 stays NOT RUN until Sash's Mac prints `A14: PASS` and `summary.txt` is from that run.

The wrappers `install.sh` and `run.sh` do not need a portability patch. They avoid `sed -i`, `stat`, `readlink -f`, `date`, `sha256sum`, and `mktemp`. The failures below are in the morning steps and in `demo.py`.

## 1. Morning step 2 leaves the only commit that contains the demo

`RUNBOOK.md` lines 5-8 tell Sash to check out `spike/agent-host` and pull. On 2026-10-26 that pull fast-forwarded a clone to `70bf2de6`. `lab/demo-a14/install.sh` was absent. The same file is absent at `23d27d8e`, which is the later tip of `spike/agent-host`. The demo commit `25d524e5` is not an ancestor of that tip. Its merge-base with the tip is `fe1e1c7e`.

Step 3 then exits 127:

```text
bash: lab/demo-a14/install.sh: No such file or directory
```

Until PR 289 is on `spike/agent-host`, step 2 has to check out the demo branch and stay there:

```bash
cd /path/to/the/clone
git fetch origin cursor/demo-a14-installed-demo-83e1
git checkout cursor/demo-a14-installed-demo-83e1
git pull --ff-only
git status --porcelain=v1
test -f lab/demo-a14/install.sh
```

`git status` has to print nothing. After the PR is merged, the `spike/agent-host` checkout in the runbook is the right step 2, and this item is done.

## 2. The `cd` path is a different folder from the one the handover names

The runbook uses `~/code/elastos-agent-host-spike`. On this VM that directory did not exist (exit 1) until a throwaway clone was created for the rest of the steps. The handover names `/Users/sash/code/wt-agent-host`.

Step 1 should say: go to the clone you already have. Name both of those paths only as examples, and stop if `lab/demo-a14/install.sh` is missing.

## 3. The long conformance run starts before the Mac is checked

`install()` in `demo.py` checks that the checkout is clean, then creates the signing key, then refuses a non-Mac that has no `--receipt`. On a Mac it goes straight into `cargo fetch` and `lab/agent-conformance/run.sh`. These facts are true before that run and are checked only later, or not at all:

- `wasm32-unknown-unknown` for the pinned toolchain. The runbook mentions it above the five steps. Step 3 is the guest build, after the conformance run. This VM's 1.91.0 toolchain does not have the target. Preflight reports that in under a second.
- `/usr/bin/shasum`, `/usr/sbin/lsof`, and `/usr/bin/sandbox-exec`. The conformance crate and the C steps call those paths.
- 40 GB free on the checkout and on the home volume. The runbook states it. The script does not read it.
- Native arm64, and `sysctl.proc_translated` not equal to 1. See item 7.
- `CARGO_TARGET_DIR` outside the repository. See item 6.
- A space in `HOME`, the checkout, `CARGO_HOME`, or the rustc sysroot. See item 8.

Add one function at the top of `install()`, before `make_signing_key` and before step 1, and return exit code 3 with one line per failure. `shutil.disk_usage(path).free < 40 * 1024 ** 3` is the disk check. The wasm target is a directory:

`$RUSTUP_HOME/toolchains/1.91.0-<triple>/lib/rustlib/wasm32-unknown-unknown`

Call the toolchain's `bin/rustc` directly, or only test the directory. Do not let the rustup proxy download a toolchain while it is being asked whether the toolchain exists.

`lab/a14-dryrun/preflight.sh` is the same list, read-only, for the Mac before the morning steps. It lives on this branch, not on PR 289.

## 4. `install.sh --sign` writes the key before it knows the install can finish

`make_signing_key` runs at `demo.py` lines 929-933, before the macOS / `--receipt` refusal at lines 936-942. The dry run's exact output:

```text
Signing is on: this machine's key is /home/ubuntu/.local/share/elastos-demo-a14/signing/receipt-signing.key ...
REFUSED: no VERSIONS.json for this machine.
```

The key file was mode `0600`, its directory mode `0700`, and `current/` was never created. There was nothing to sign. The next `run.sh` says the demo is not installed and tells the reader to run `install.sh` again, which repeats the refusal.

Move the `make_signing_key` call, and the "Signing is on" line, to just before `write_install`. A failed conformance run then leaves no new key. A key that already exists still means signing stays on, which is what the runbook already says. Add a unit test that `install(..., sign=True)` on a non-Mac host, with no receipt, returns exit 3 and does not create `signing/receipt-signing.key`.

## 5. A refusal before any journey writes no summary, and step 5 opens an empty path

`run_demo` returns at the first `refuse()` call (`demo.py` lines 767-776), before `runs/` is created and before `summary.txt` is written at line 855. The dry run confirmed there was no `runs/` directory. Step 5 is:

```bash
open "$(ls -dt ~/Library/Application\ Support/elastos-demo-a14/runs/*/ | head -1)"
```

`ls` failed, the substitution was empty, and `open` was executed with no path (here it is `xdg-open`, which printed usage, exit 1). macOS `open` with no path does the same kind of thing: it does not show the refusal.

Write the refusal text to a file under the demo home before returning, and print that path in the `Next:` line. Change step 5 to open that file only when it is a real path:

```bash
run=$(ls -dt "$HOME/Library/Application Support/elastos-demo-a14/runs/"*/ | head -1)
test -n "$run" && test -d "$run" && open "$run"
```

## 6. The parent environment can change where Cargo puts the binaries

`suite_env` (`demo.py` lines 559-563) copies `os.environ` and then sets the suite's own variables. An absolute `CARGO_TARGET_DIR` outside the checkout makes step 4 refuse with "outside the repository", after the conformance run and the guest build. `CARGO_TERM_COLOR=always` colors the `Running` line that `cargo_ran_problems` (`demo.py` lines 575-587) matches, so A8 can be marked unbound after it ran.

At the start of `install()`, if `CARGO_TARGET_DIR` is absolute and not inside the repository, refuse with the variable and the path. In `suite_env`, set `CARGO_TERM_COLOR` to `never` for the commands this demo runs.

Neither variable was set in the dry run. The behavior follows from reading `suite_env` and `cargo_ran_problems`.

## 7. A Rosetta shell is accepted

No architecture check exists. Rosetta reports `x86_64` and `sysctl.proc_translated=1`, and the binaries hashed into the receipt are x86_64 binaries. `components.json` has a `darwin-arm64` row for `localhost-provider` and no `darwin-amd64` row. The conformance helper inserts a missing platform, so the install may still get through and bind the translated binaries.

Refuse in the same early check as item 3 unless `platform.machine() == "arm64"` and `sysctl -n sysctl.proc_translated` is not `1`. Say "open a native arm64 Terminal".

## 8. A space in HOME or in the checkout breaks the guest build

`scripts/build-component-capsule.sh` appends `--remap-path-prefix=$HOME=...`, the Cargo home, the repository, and the rustc sysroot to `RUSTFLAGS`. rustc splits that variable on spaces. The wrappers and `demo.py` quote their own paths, including `Application Support`. The guest build does not.

Refuse in the early check when any of those four paths contains a space, and name the path. `/Users/sash` has no space, so this does not by itself stop the known Mac checkout. It is the paths-with-spaces hole in the install step 3 command.

## 9. A downloaded zip can mark the tree as quarantined

The scripts never download a publisher binary, and they never strip `com.apple.quarantine`. A git clone is clean. A browser download of a zip often sets the attribute, and `shutil.copy2` preserves it onto the installed copy.

Add one sentence under "What you need": use `git clone` or `git checkout`. A zip from a browser can make macOS refuse to run the built programs. Do not delete the attribute from the script; preflight only reports it.

## Order to apply

Items 1 and 2 are the runbook text. Items 3, 4, 6, 7, and 8 are one early function in `install()`. Item 5 is the refusal path in `run_demo` plus step 5. Item 9 is one sentence in the runbook. The shell wrappers can stay as they are.
