# redteam — a lab-only red team

This folder holds adversarial probes against work **already merged** on
`spike/agent-host`. It verifies, or falsifies, the evidence a grade rests on; it
never raises a grade and never patches an owner tree. A clean probe says only
"this probe did not break it on commit X". A probe that reproduces a defect is a
**finding**, pinned to the exact merged commit and PR it attacks, with an exact
repro; the owner lane decides the fix.

Everything this lane writes stays under `lab/redteam/`. Other trees are **read
only** (the profile under test is read, never edited).

## What 001 probes

The merged **wallet-provider** seatbelt profile
`capsules/wallet-provider/confine.sb`, attacked **directly** with
`/usr/bin/sandbox-exec` and stock binaries — not over the provider's own
protocol. The owner's `tests/confine.rs` drives the happy path over the
protocol (`confined_outside_read_is_denied`, `confined_outside_write_is_denied`);
this lane goes **beyond** it, trying the escapes those tests do not:

- read and write **through a symlink that resolves out of `STORAGE_ROOT`**;
- read a **sibling file under `STORAGE_PARENT`** (the parent grant is the
  directory *literal*, not a subpath, so a sibling file must stay denied);
- break the **exec pin** (exec a binary other than `PROVIDER_EXECUTABLE`).

Positive controls (an in-root read, an in-root write, the pinned exec) prove the
denials are not vacuous. Each attack has a **falsifier**: a disposable profile
derived from the real one with the single forbidding rule weakened, run through
the same runner, shown to let the escape through — so a regression that weakened
the real profile would flip the attack test red.

## Pin (guard a)

- profile: `capsules/wallet-provider/confine.sb`
- commit: `09ad101c24cde4375befd98be3bb6d69ef1e0a06` — PR #86 (confine/016), last
  change to the bytes; the profile was introduced in PR #63 (confine/004) and
  `(deny network*)` added in PR #83.
- sha256 of the tested bytes: `5a0140c6b02b60508e6fcd3ff8896504406430e14eaa87749ee10ab419cf319a`

## How to run

```
python3 -I -m unittest discover -s lab/redteam/py
```

`python3 -I` means the current directory is not importable; the tests find the
repo root and the profile from `__file__` (`parents[3]`), and `unittest
discover -s lab/redteam/py` puts that dir on `sys.path` so `import sbx` resolves.
There is no `lab/redteam/Cargo.toml`, so the lane's `cargo` gates are no-ops
until a later task deliberately adds one (one workspace root — P10).

## Honesty rules this lane keeps

- **SKIP is never PASS (guard d).** `sandbox-exec` is macOS-only. If it is
  absent, or a stock binary cannot even start under the profile on this OS, the
  whole suite SKIPs with that reason — the deny results would otherwise be
  vacuous. A positive control that fails for any other reason is a real failure,
  not a skip.
- **A harness error is never confinement.** A denial is told from a broken
  fixture by its reason: a seatbelt deny surfaces `Operation not permitted`
  (and the program leaks no bytes / changes no outside file); a missing profile
  or missing binary says `No such file or directory` and is rejected by the
  deny check, so it shows as a failure, never a pass.
- **Findings stay here (guard b).** A reproduced defect is written to
  `findings/<owner-lane>-<nnn>.md` (naming the owner lane), kept as a probe
  marked `@unittest.expectedFailure` carrying the finding id, and never deleted.
  Expected-failure is reserved for a confirmed, recorded escape — an unrelated
  error must still fail.
- **Escapes are CRITICAL and not batched (guard c).** A confinement escape — an
  allow where a deny is required — is written at once as its own
  `findings/CRITICAL-*.md`, appended to `lab/redteam/CRITICAL.md`, with
  "CRITICAL" in the commit subject.

### Severity of an allowed sibling read

The task text left this ambiguous (Goal: an escape = CRITICAL; acceptance item
4: "a normal finding"). Resolved here toward guard (c): reading a **sibling
file's contents** under `STORAGE_PARENT` is a read of content **outside**
`STORAGE_ROOT`, i.e. a confinement escape, so an allow is classified
**CRITICAL**. (Reading the `STORAGE_PARENT` directory entry itself is granted and
expected; the probe reads a sibling *file*, so an allow is unambiguously a leak.)
On this commit the read is denied, so no finding is written.

## Files

- `py/sbx.py` — the one direct `sandbox-exec` runner (P10: a single copy;
  sibling tasks 002/003 do not import it, a later provider-confine task reuses
  it). Not a test (name does not match `test*.py`).
- `py/test_confine_wallet_profile.py` — the controls, attacks, falsifiers, and
  harness-honesty tests.
- `findings/` — findings land here (empty on a clean run).
