# Jetson proof kit

One script for a human to run on the Jetson Orin Nano (aarch64, JetPack
R36.4.7, 7.4 GiB RAM). The script stays inside `~/flint-elastos-test`, records
the kernel and the Landlock ABI, then builds and runs the C0 guard from draft
PR #307 and the C9 launcher from draft PR #296.

This folder is the kit. The board run is still NOT RUN.

## Operator steps

Copy this folder onto the board as `~/flint-elastos-test` (or copy it into
that folder). Then:

```bash
cd ~/flint-elastos-test
./run-on-jetson.sh
```

The script writes `~/flint-elastos-test/evidence.txt`. Each row is `PASS`,
`REFUSED` with a reason, or `NOT RUN`.

Set `JPK_REMOTE` when git should fetch the draft branches from a clone the
board already has. The pins are:

- C0: `cursor/fail-closed-linux-0b95` at `129fdc98428c9029b328976511478c46ebe765a6`
- C9: `cursor/linux-confine-e156` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`

The Landlock probe is the one from draft PR #314. `uname -r` is not the ABI.

## What a refusal means

The C0 and C9 guards keep their ABI floor of 5. When the board reports an ABI
below 5, the guard refuses the start and names the missing right. That refusal
is the evidence row. The kit does not lower the floor.

## Bounds

The script runs as the calling user. It keeps every write, clone, cargo home,
and build directory under `~/flint-elastos-test`. Cargo and gcc use four jobs.
A `MemAvailable` reading below 1 GiB stops the run. The script leaves the rest
of the board alone.

## Checks that run off the board

```bash
bash lab/jetson-proof-kit/tests/test_guards.sh
bash lab/jetson-proof-kit/falsify.sh
```

The first command covers the path guard, a planted path outside the folder,
the memory floor, and the committed Jetson rows. The second command plants
two bugs on a copy: an outside path that is accepted, and a missing memory
check. Both plants are caught. The working tree stays unchanged.
