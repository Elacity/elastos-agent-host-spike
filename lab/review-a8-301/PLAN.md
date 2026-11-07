# Plan (executed in this session)

Reviewed head: `1a82d25bdd00d3a383433de84e97c39a4184d107` (`cursor/a1-a8-hardening-85ce`).
Checkout: detached worktree `/tmp/pr-301-a8`. No push to that branch.

## Claims to score (HOLDS / FALSIFIED / WEAK)

From #301 at this head and the #316 findings it says it closed:

1. A1: WASI import refused with the allowlist sentence; bus-only build admitted.
2. A1: the row is not "every component is refused" (`F-A1a`).
3. A8: committed injection's refusal sentence is produced by the Runtime; fake key unchanged.
4. A8: the test proves the Runtime produced that sentence (`F-A8-forge`).
5. A8: the injection fails only the fake key and goes through the real grant path (`F-A8-early`).
6. A8: shipped adapter prints the Internal sentence (author says NEEDS RUNTIME).
7. A8 shipped-bytes row is a pass (author says it is BLOCKED).
8. Falsifiers 6/6 CAUGHT; suite 2 passed, 1 BLOCKED; cargo exit 0.

Anders's rule for bookability: a check counts only when its complete journey,
refusal evidence, and required reviews all pass.

## Commands to run (record exact output; anything not executed is NOT RUN)

```sh
# from /tmp/pr-301-a8 after cargo fetch --locked of the needed manifests
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/falsify.py F-A1a
python3 lab/a1-a8-hardening/falsify.py F-A1-runtime
python3 lab/a1-a8-hardening/falsify.py F-A8a
python3 lab/a1-a8-hardening/falsify.py F-A8-runtime
python3 lab/a1-a8-hardening/falsify.py F-A8-forge
python3 lab/a1-a8-hardening/falsify.py F-A8-early
```

## Break attempts (scratch copies in the worktree; restore SHA-256)

- Guest forges the sentence from pieces so the wasm lacks the contiguous prefix.
- Guest asks via a second `capabilities::request?` and never calls `request_journal_grants` on the bus.
- Guest keeps `host_path` / `JOURNAL_ROOT` guards and still gets the exact stderr line.
- Guest drops the extra `?` and uses only shipped `WasmBus`.
- Timeout / pending-request rows counted as CAUGHT against the runner's own rule.
- Cited tests that do not exist; BLOCKED row that is a hidden FAIL.

macOS A8 is out of this machine. Mark NOT RUN. No aarch64.
