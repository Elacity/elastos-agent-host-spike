# Review r4 of draft PR #296 (C9 Linux confine on aarch64, emulated)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

Write-up: [REVIEW.md](REVIEW.md)

Reviewed head: `c7c07e3b5ed970929c5154e21406e47721757889`

Label: `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`

Native aarch64 / Jetson: NOT RUN.
`make-char` / `make-block`: NOT RUN.
`socketpair(AF_UNIX)`: named C9 departure.
