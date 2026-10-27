# Adversarial review r5 of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290-r5
Branch / PR:  cursor/review-a9-290-r5-9855  (draft, this PR)
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         78bc82bfb38047f9b8c367213bd06604e85a98cd
Tree:         /tmp/pr-290-r5 (detached, not pushed)
Base of #290: spike/agent-host merge-base b5069b992dac29d1457576efabd5700e34ea05e7
This branch:  origin/spike/agent-host a165fb8d
Machine:      Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), kernel 6.12.94+, no KVM
elastos:      not on PATH
```

Counts and attack verdicts below are filled after `run.py` and `mutants.py` on
this session. The probe and mutant lists are the harness.

## Verdict

Pending this session's run. A9 stays unbooked until the report names PASS or FIX.

## What this review attacks

The r4 fix binds `{root}.owned` to `(dev, ino)` + owner + exact relative path +
generation stamp (ctime, statx birth time, 16-byte `user.owned-storage.nonce`).
This round reruns the author's 25/0/0, 12/12 plants, 14/14 mutants, race, and
bind-mount claims, then hunts the new record: nonce forge/copy, filesystems
without user xattrs, ctime/btime collisions, partial `.owned` writes, create/unlink
races, rename across agents, host hard links, and a newline-injected `.owned` line.

Runtime rows must stay Blocked. Nothing may claim A9 is booked.
