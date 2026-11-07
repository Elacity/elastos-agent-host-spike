# lab/review-c0-307

Independent adversarial review of draft PR #307 (C0 fail-closed
Linux guard, per-right floor) and draft PR #320 (Jetson proof kit).

This folder is the only tree this session writes. The two reviewed
branches were checked out read-only under `/tmp/review-c0-307-src/`.
Nothing under `lab/fail-closed-linux/` or `lab/jetson-proof-kit/`
was edited.

```text
Reviewed #307: 2c70a0d845f9acc15144a2afec889370612cca66
Reviewed #320: 34a89256e66037e97d52eb9d3e2c0da1267b56a7
Machine:       Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6
Aarch64:       NOT RUN
Jetson:        NOT RUN
```

## Run

From the repository root, after the two worktrees exist (or after
setting `FCL_SRC` and `JPK_SRC`):

```bash
lab/review-c0-307/run.sh
```

`run.sh` reads the reviewed sources, compares the ABI table to the
kernel 6.12 uapi and to this host's Landlock probe, checks that the
kit's ABI 1 fixture never calls the guard, and plants F-RV-F18 on a
copy of #307 (the copy is under `/tmp`). It does not register
`binfmt_misc` or qemu.

## Read first

`REPORT.md` is the review. It has the findings table, a fix list for
each PR, and the fail-closed statement for this VM.
