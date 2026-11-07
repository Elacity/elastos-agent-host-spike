# Plan (executed in this session)

Reviewed head: `10316585addf30c0f1e6446793cce302c0035acf` (`cursor/a1-a8-hardening-85ce`).
Checkout: detached worktree `/tmp/pr-301-a8-r3`. No push to that branch.
Never touch `Elacity/elastos-runtime`.

This is r3 of the A8 review. Prior reviews:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) (r1) at `1a82d25b`,
[PR #388](https://github.com/Elacity/elastos-agent-host-spike/pull/388) (r2) at `a2398b5d`.

Anders's rule: a check counts when its complete journey, its refusal
evidence, and its required reviews all pass.

## Claims to score (HOLDS / FALSIFIED / WEAK)

From #301 at this head, after the #388 binding fix:

1. Suite counts: 1 PASS, 2 NEEDS RUNTIME, 1 BLOCKED, cargo exit 0.
2. Falsifiers 12/12 CAUGHT by real assertions. Timeouts are NOT CAUGHT.
3. Fresh `mktemp` Home; fail if jsonl pre-exists; size/inode recorded;
   only appended lines read.
4. Receipts must match component id + session id + guest hash, or the
   row stays NEEDS RUNTIME.
5. Honest sequence required (`request_journal_grants` then the follow-up
   sentence).
6. A1 PASS is genuine: WASI import refused at admission by this
   checkout's `elastos` binary, not a lab shim.
7. A8 host-key row stays NEEDS RUNTIME. Shipped-bytes row stays BLOCKED.

## Hunts

- Can a row still reach PASS with NEEDS RUNTIME conditions unmet
  (env var, missing field treated as match, empty session == empty session)?
- Is the inode/size check racy (file created between check and launch)?
- Does the sequence check rely on stdout/stderr text the guest controls?
- Are timeouts counted as catches?
- Replant r1/r2 attacks.
- Write at least six mutants of the binding check.
- Judge RUNTIME-ASK accuracy and minimality.

## Commands

```sh
# from /tmp/pr-301-a8-r3 after cargo fetch --locked of the needed manifests
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/falsify.py <ID>   # each of the twelve
```

Re-plant r1/r2 attacks as scratch edits in the worktree. Restore SHA-256
after each. Binding mutants stay in this review folder's evidence.
macOS A8 is out of this machine. Mark NOT RUN.
