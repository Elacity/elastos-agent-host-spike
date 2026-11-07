# Review r5 of draft PR #442 (C9 emulated-aarch64 checker leftovers)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/c9-r4-fail-closed-9b97` (#442) or
`cursor/linux-confine-e156` (#296).

Write-up: [REVIEW.md](REVIEW.md)

Reviewed head: `f19dff97d73de968b588974bbc4657ce5cebdbfb`
Checker: `7ad5d7ad7792484c938d075badcfe90937f25bac`

Label: `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`

**VERDICT: PASS** for the emulated aarch64 half only.

Native aarch64 / Jetson: NOT RUN.
`make-char` / `make-block`: NOT RUN.
`socketpair(AF_UNIX)`: named C9 departure.
