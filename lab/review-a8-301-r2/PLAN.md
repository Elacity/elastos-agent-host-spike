# Plan (executed in this session)

Reviewed head: `a2398b5d6c59c2794077b3b3fd38880dd7bbc4b1` (`cursor/a1-a8-hardening-85ce`).
Checkout: detached worktree `/tmp/pr-301-a8-r2`. No push to that branch.

This is r2 of the A8 review. Prior review:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) at `1a82d25b`.

## Claims to score (HOLDS / FALSIFIED / WEAK)

From #301 at this head and the author's #356 closure:

1. Suite counts: 2 PASS, 1 NEEDS RUNTIME, 1 BLOCKED, cargo exit 0.
2. Falsifiers 10/10 CAUGHT by real assertions. Timeouts are NOT CAUGHT.
3. The four #356 plants are dead on the host-side receipt.
4. Runtime appends each `request_capability` to `runtime/capability-requests.jsonl`.
5. Guest has no filesystem and cannot write that file.
6. Pass row requires write-then-read of the fake key, both `manifest_capability_denied`.
7. The record is written by shipped Runtime code, not a lab shim.
8. The record is bound to this guest and this session.

## New hunts

- Can the guest reach the jsonl through a granted capability, preopen, bus call, or a Home path it can name?
- Can the harness process write the record (pre-seed, stale file, no truncate, unbound lines)?
- Is the record bound to the guest module hash and this session id?
- Does a real Runtime build reproduce it?

## Commands

```sh
# from /tmp/pr-301-a8-r2 after cargo fetch --locked of the needed manifests
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/falsify.py <ID>   # each of the ten
```

Re-plant A/B/C/D from #356 as scratch edits in the worktree. Restore SHA-256 after each.
macOS A8 is out of this machine. Mark NOT RUN.
