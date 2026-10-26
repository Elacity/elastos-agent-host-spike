# lab/review-jetson-kit-320-v2

Independent adversarial review of draft PR #320 (Jetson proof kit)
at `2bb0b5859bbf8582a43d958e3ddc1569eb77bf97`. This folder is the
only tree this session writes. The #320 branch was not edited.

```text
Reviewed #320: 2bb0b5859bbf8582a43d958e3ddc1569eb77bf97
Compared #307: 2c70a0d845f9acc15144a2afec889370612cca66
Machine:       Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6
Aarch64:       NOT RUN
Jetson:        NOT RUN
```

## Run

The reviewed kit and #307 crate are read-only worktrees. Set the
paths if they differ:

```bash
export JPK_SRC=/tmp/jpk-320/lab/jetson-proof-kit
export FCL_SRC=/tmp/c0-307/lab/fail-closed-linux
lab/review-jetson-kit-320-v2/run.sh
```

`run.sh` re-runs the kit tests on the read-only tree, compares
`decide.py` to #307 `missing_rights_reason`, checks the live-Jetson
guards, and plants the new review falsifiers on copies under `/tmp`.

## Read first

`REVIEW.md` is the review. It has one verdict per claim, the safety
check, and a go or no-go for the board.
