# Plan (executed in this session)

Reviewed head: `b0cc24c2a6ba5088e15146990c89cbbc1435769f` (`cursor/a1-a8-hardening-85ce`).
Code head: `460746b2124aefbf47683a467fe40a6407ea3f97`.
Checkout: detached worktree `/tmp/pr-301-a8-r4`. No push to that branch.
Never touch `Elacity/elastos-runtime`. Never merge or close a PR.

This is r4 of the A8 review. Prior reviews:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) (r1) at `1a82d25b`,
[PR #388](https://github.com/Elacity/elastos-agent-host-spike/pull/388) (r2) at `a2398b5d`,
[PR #408](https://github.com/Elacity/elastos-agent-host-spike/pull/408) (r3) at `10316585`.

Anders's rule: a check counts when its complete journey, its refusal
evidence, and its required reviews all pass.

## Claims to score (HOLDS / FALSIFIED / WEAK)

From #301 at `b0cc24c2`, after the #408 r3 fix:

1. Suite: 1 PASS, 2 NEEDS RUNTIME, 1 BLOCKED. Host-key cargo test FAILS
   (refuses PASS). `run.sh` remaps that to NEEDS RUNTIME and exits 0.
2. 14 of 14 plants CAUGHT by real assertions. Timeouts are NOT CAUGHT.
3. 7 of 7 binding mutants KILLED.
4. Sequence judged only from host receipts and the Runtime / bus host log.
   Guest stderr is ignored.
5. Missing assigned id is not a match. Receipts after the snapshot, or
   with a foreign `capsule_id`, fail.
6. Cargo test itself FAILS while component id, session id, module hash,
   or guest function is missing. `session_id` must equal this launch.
7. RUNTIME-ASK.md states those as required asserts.
8. A1 PASS. A8 stays NEEDS RUNTIME / BLOCKED. macOS NOT RUN.

## New attacks (this round)

Each gets CAUGHT or SURVIVED with the exact patch.

1. Guest writes the host log path or the receipts file (preopen / symlink).
2. Forged receipt line whose `session_id` is copied from env / argv the
   guest can read.
3. Session id predictable, or reused across launches.
4. `module_hash` computed over a different file than the one executed
   (TOCTOU swap between hash and load).
5. Receipts with duplicate or out-of-order sequence numbers.
6. Host log rotated or truncated mid-run.
7. JSON with duplicate keys (first vs last wins).
8. `capsule_id` case or whitespace variants.

## Commands

```sh
# from /tmp/pr-301-a8-r4 after cargo fetch --locked of the needed manifests
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/mutants/binding.py
python3 lab/a1-a8-hardening/falsify.py <ID>   # each of the fourteen
python3 lab/review-a8-301-r4/attacks/new_hunts.py
```

macOS A8 is out of this machine. Mark NOT RUN.
A8 stays NEEDS RUNTIME / BLOCKED even if the lab half is PASS.
