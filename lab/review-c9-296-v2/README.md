# Adversarial review of PR #296 C9 fixes (v2)

Draft only. Do not merge. This folder reviews draft PR #296 at
`0785eecd`. It does not edit `lab/linux-confine/` or any other lab folder.

```text
Lane:         lab/review-c9-296-v2
Branch / PR:  cursor/review-c9-296-v2-94b0  https://github.com/Elacity/elastos-agent-host-spike/pull/349
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         0785eecd4e40943adc93c455363a0bff4675cba8
Tree:         /tmp/wt/linux-confine-296-v2
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6
```

The first review is draft PR #326 (`lab/review-c9-296/`). This folder re-ran
the claimed suite on the fix head and planted new mutants.

```bash
git fetch origin cursor/linux-confine-e156
git worktree add --detach /tmp/wt/linux-confine-296-v2 0785eecd
export LC_REVIEW_TREE=/tmp/wt/linux-confine-296-v2
python3 -I lab/review-c9-296-v2/run.py
python3 -I lab/review-c9-296-v2/extra.py
python3 -I lab/review-c9-296-v2/mutants.py
python3 /tmp/wt/linux-confine-296-v2/lab/linux-confine/falsify.py
```

Verdicts live in `REVIEW.md`. C9 is not bookable: aarch64 and Jetson stay
NOT RUN, and `socketpair(AF_UNIX)` is a named C9 / B4 departure.
