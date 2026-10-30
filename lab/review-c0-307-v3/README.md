# lab/review-c0-307-v3

Independent adversarial review of draft PR #307 at
`1894f4323026b6c4df90a3487d8899a4bd8ee1c8` (the five #338 fixes on top of
the PID-namespace work). This folder is the only tree this session writes.

The reviewed crate was checked out read-only under
`/tmp/review-c0-307-v3-src/` (git worktree, detached at 1894f432). Nothing
under `lab/fail-closed-linux/` was edited. PID-namespace reapers and a
lying-ABI real-rights probe belong to `lab/review-c0-307-pidns`.

```text
Reviewed:  Elacity/elastos-agent-host-spike#307
Head:      1894f4323026b6c4df90a3487d8899a4bd8ee1c8
Parent:    637345ac (PID namespace + F03 retarget)
Machine:   Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6
Aarch64:   NOT RUN
Jetson:    NOT RUN
macOS:     NOT RUN
```

## Run

From the repository root, after the worktree exists (or after setting
`FCL_SRC` to a writable copy of that crate):

```bash
lab/review-c0-307-v3/run.sh
```

`REPORT.md` is the review. `test_ioctl_dev_is_landlock.py` is a standalone
failing test: on this head the confined probe's `ioctl_dev` line is
`errno=25` (`ENOTTY`), the same as an unconfined `FIONREAD` on `/dev/null`.
