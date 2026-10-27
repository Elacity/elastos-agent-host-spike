# redteam: a lab-only red team

This file is the one in-repo home of the cc-redteam lane's goal and of Rong's
guards (a) to (e). The lane's task queue lives with the orchestrator, outside
this repo, so a reader finds here every rule the probes claim to keep.

## Lane goal

A lab-only red team. It writes adversarial probes and falsifier tests against
work **already merged** on `spike/agent-host`, and keeps every file it writes
under `lab/redteam/`. It changes no owner tree and never patches. It does not
raise a grade; it independently verifies, or falsifies, the evidence a grade
rests on. A clean probe says only "this probe did not break it on commit X". A
probe that breaks something is a finding, pinned to the exact merged commit and
PR it attacks, with an exact repro. The owner lane decides the fix.

Target areas (owner lane in brackets):

- confine: the provider seatbelt profiles `capsules/wallet-provider/confine.sb`
  and `capsules/did-provider/confine.sb`, and the shared contract check
  `capsules/wallet-provider/tests/confine.rs` [confine]; the model-provider
  profile `capsules/model-provider/confine.sb` [cc-model-confine].
- provider: `capsules/model-provider` behaviour proofs and its
  `falsifiers.json` [provider].
- agent-host: `examples/agent-host` falsifier and asks honesty [agent-host].
- wasm-capsule lab: the build and receipt in `lab/wasm-capsule`
  [wasm-capsule-lab], and its import pre-check `lab/wasm-capsule/audit`
  [cx-wasm-audit].

## Rong's guards

- **(a) Pin the target.** Every finding pins the merged commit hash and the PR
  number it attacks, plus the sha256 of the tested bytes. Get them in a
  worktree whose HEAD sits on the current base:
  `git log -1 --format='%H %s' HEAD -- <file>` and `shasum -a 256 <file>`.
  Do not ask the local `spike/agent-host` branch: it is stale and returns
  nothing.
- **(b) Findings stay here.** A finding goes in
  `findings/<owner-lane>-<nnn>.md`, naming the owner lane. No patch, no edit
  to any `confine.sb`, nothing dropped in an owner tree: the owner decides the
  fix. A probe that reproduces a defect stays as a test marked
  `@unittest.expectedFailure` whose docstring names its finding file, so the
  gate stays green. It is never deleted. Expected-failure is only for a
  confirmed, recorded escape: an unrelated or setup error must still fail.
- **(c) Escapes are CRITICAL and not batched.** A confinement escape (an allow
  where a deny is required), an ambient-authority path, or a capability token
  accepted outside the Runtime is CRITICAL. Write it at once as its own file,
  `findings/CRITICAL-confine-<nnn>.md` for a confine escape, with "CRITICAL" in
  its first line, and append it to `CRITICAL.md` in this folder. The lane
  runner writes every commit subject and a builder cannot commit, so the
  CRITICAL file name and `CRITICAL.md` are the signal. The builder also starts
  its final reply with CRITICAL.
- **(d) A SKIP is never a PASS.** Report SKIPPED with the reason, and only for
  a real platform limit. A run where everything skips is not a pass. Positive
  controls must run, or the deny results are vacuous. A broken fixture is a
  failure, never a skip.
- **(e) No network, no secrets.** No network access. No real keys or secrets:
  a test key is generated in a temp dir inside the test and never committed
  (`.gitignore` carries `*.key` and `*.seed`). Nothing aimed at hosts outside
  the lab. Mac toolchain only, no Docker.

## Scope

Every file this lane writes stays under `lab/redteam/`. Other trees are read
only. Never edit `capsules/`, `examples/`, `elastos/`, `lab/wasm-capsule/`,
`lab/agent-conformance/`, `scripts/`, `docs/`, or any Runtime file. No
security weakness of the shipping product goes in a finding: the targets are
private lab and spike work, pinned by commit.

There is no `lab/redteam/Cargo.toml` yet, so the lane's cargo gates do
nothing. A later task adds one on purpose (one workspace root, P10).

## How to run

```
python3 -I -m unittest discover -s lab/redteam/py
```

`-I` means the current directory is not importable. The tests find the repo
root from `__file__` (`parents[3]`), and `discover -s lab/redteam/py` puts
that folder on `sys.path`, so `import sbx` works. Report the pass, skip and
fail counts: an all-skip run also exits 0, so the exit code alone is not a
pass (guard d).

## Wallet `confine.sb` probe

`py/test_confine_wallet_profile.py` attacks the merged wallet-provider profile
`capsules/wallet-provider/confine.sb` directly, with `/usr/bin/sandbox-exec`
and the stock binaries `/bin/cat`, `/usr/bin/touch` and `/usr/bin/true`, not
through the provider's protocol. The owner's `confined_outside_read_is_denied`
and `confined_outside_write_is_denied` in
`capsules/wallet-provider/tests/confine.rs` cover the happy path. This probe
tries the escapes they do not:

- read and write through a symlink inside `STORAGE_ROOT` that points out of it;
- read a sibling file under `STORAGE_PARENT` (the parent grant is the
  directory literal, not a subpath, so a sibling file must stay denied);
- run a binary other than `PROVIDER_EXECUTABLE` (the exec pin).

Every launch binds the Runtime's three parameters (`PROVIDER_EXECUTABLE`,
`STORAGE_ROOT`, `STORAGE_PARENT`), copied from the owner's
`start_with_profile` and `CANONICAL_PARAMS`. Three positive controls (an
in-root read, an in-root write, the pinned exec) show the denials are not
vacuous. Each attack has a falsifier: a temp copy of the profile with one
allow added, shown both to let the escape through and to turn the named attack
test red. The real profile is read, never edited.

Outcome rule: any allow on an attack is a confinement escape, so it is
CRITICAL (guard c). That includes the sibling-file read, because it reads
content outside `STORAGE_ROOT`. Reading the `STORAGE_PARENT` directory entry
itself is granted and expected.

### Pin (guard a)

`DidConfineProbe` and `ModelConfineProbe` reuse this probe.

The three profiles are the live files under `capsules/`. `py/test_confine_mach.py` is the one place that computes a live commit and a live sha256 for a report. `py/test_confine_wallet_profile.py` and `py/test_confine_network.py` call that file's `changed` and `sha256_file`. They record the digest at module start and compare it at module end. They store no digest. An owner change to a profile is not a failure of this check. A difference between the start and the end raises `the probe changed <rel>`.

### How the probe tells a deny from a harness error

- **A real deny** (Darwin 25): nonzero exit, and an `Operation not permitted`
  line that names the path or binary. The launched program prints it for a
  file (`cat: <path>: Operation not permitted`, exit 1), and `sandbox-exec`
  prints it for a blocked exec (`sandbox-exec: execvp() of '<binary>' failed:
  Operation not permitted`, exit 71). A denied read must leave stdout empty: a
  partial leak fails too. A denied write must create nothing outside the root.
- **A profile error is a harness error, whatever its text says.** When
  `sandbox-exec` cannot read, compile or evaluate the profile, it exits 65 and
  starts no program. Its message can still say `Operation not permitted`: a
  profile holding `(error "link-read: Operation not permitted")` prints exactly
  that. So both classifiers, the canary and `require_denied`, first ask the
  runner's one rule, `sbx.profile_error`. It names the error: "profile
  evaluation error" when `sandbox-exec` prints a backtrace, else "profile read
  or compile error". Such a run is never a deny and never a SKIP.
- **A missing binary** says `No such file or directory`: a harness error,
  never a deny.
- **SKIP only for a real platform limit:** no `sandbox-exec`, no stock binary,
  or seatbelt refusing to start a stock binary under a profile that loaded.
  One example is `sandbox-exec: sandbox_apply: Operation not permitted`
  (exit 71) when the shell already runs inside a sandbox. Then every deny
  would be vacuous.

The honesty tests prove these rules through unittest itself:

- `test_harness_errors_are_failures`: `require_denied` refuses a missing
  profile, naming a profile read or compile error, and a missing binary.
- `test_partial_read_leak_is_not_a_deny`: one leaked byte is not a deny.
- `test_missing_profile_setup_errors_through_unittest` and
  `test_malformed_profile_setup_errors_through_unittest`: a broken fixture
  makes the preflight ERROR, never SKIP.
- `test_profile_evaluation_error_setup_errors_through_unittest` and
  `test_profile_evaluation_error_is_not_a_deny`: a profile evaluation error
  whose text says "Operation not permitted" is never a SKIP and never a deny.
- `test_unrelated_error_is_not_expected_failure`: a setUp error in an
  expected-failure probe still ERRORs.
- `test_expected_failures_are_recorded_findings`: every expected-failure probe
  names a finding file that exists.

## Files

- `README.md`: this file, the lane goal and guards (a) to (e).
- `.gitignore`: `*.key` and `*.seed` (guard e), and Python caches.
- `findings/`: findings land here. It holds only `.gitkeep` on a clean run.
- `CRITICAL.md`: not present. The first CRITICAL finding creates it (guard c).
- `py/sbx.py`: the one `sandbox-exec` runner and its profile-error rule (P10,
  one copy). It takes any profile path; the planned did and model-provider
  profile probes reuse it. Not a test: its name does not match `test*.py`.
- `py/test_confine_wallet_profile.py`: the wallet probe above.
- `py/test_wasm_capsule_receipt.py`: task 003's probe of the wasm-capsule
  receipt hash binding (PR #124).
