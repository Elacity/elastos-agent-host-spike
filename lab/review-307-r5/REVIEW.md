# Independent adversarial review r5 of C0 (#307)

Independent adversarial review r5 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux launch) at `747cda4f`.

Draft only. Do not merge this review PR. This folder is the only tree
this session writes. `lab/fail-closed-linux/` was left as the author
wrote it. Branch `cursor/fail-closed-linux-0b95` was not pushed.

```text
Lane:           lab/review-307-r5
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Head:           747cda4f0f2dfb5953baad1c62c44be1a0d84e71
Parent:         dc5fe676e8ad13e5882871a27b9f2dd166780bf5
Tree:           /tmp/wt-307-r5/candidate  (detached worktree)
Machine:        running
Aarch64:        running (emulated CPU, qemu-system TCG)
Jetson:         emulated 5.15 kernel stand-in, not a board
```

## Plain English

This file is the running review. Counts, hunts, and the verdict land in
the next commit once the official suite, F36/F37 replant, live hunts,
and the two qemu guests finish.

The claimed r4 leftovers: a second seccomp filter that returns EPERM
for `execveat` and `memfd_create(MFD_EXEC)`; a terminal on fd 0/1/2
replaced with `/dev/null`; only fds 0-2 after start; self-test also
covers execveat of a memfd, REFER, and make_*. Claimed counts: lib 9,
simulated 21, real_kernel 28, falsify 33/33 plus control.

## Verdict

Pending the rerun. This draft is the harness only.
