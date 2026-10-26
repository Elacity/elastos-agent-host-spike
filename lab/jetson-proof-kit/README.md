# Jetson proof kit

One script for a human to run on the Jetson Orin Nano (aarch64, JetPack
R36.4.7, 7.4 GiB RAM). The script stays inside `~/flint-elastos-test`,
records the kernel and the confinement facts, prints a launch/refuse table
for did, wallet, and model under both floor options, then builds and runs
the C0 guard and the C9 launcher.

This folder is the kit. The board run is still NOT RUN.

## Operator steps

Copy this folder onto the board as `~/flint-elastos-test` (or copy it into
that folder). Then:

```bash
cd ~/flint-elastos-test && ./run-on-jetson.sh
```

The default C0 pin is #307 commit
`2c70a0d845f9acc15144a2afec889370612cca66` (the per-right floor). To fetch
the current #307 head instead:

```bash
cd ~/flint-elastos-test && JPK_C0_PR=307 ./run-on-jetson.sh
```

The old ABI 5 pin `129fdc98428c9029b328976511478c46ebe765a6` still builds,
but the kit refuses to print a per-right table against that floor.

The script writes `~/flint-elastos-test/evidence.txt`. Each row is `PASS`,
`REFUSED`, `ABSENT`, or `NOT RUN`. A measured-absent right is `ABSENT`,
never `PASS`.

Set `JPK_REMOTE` when git should fetch the draft branches from a clone the
board already has. The default pins are:

- C0: `cursor/fail-closed-linux-0b95` at `2c70a0d845f9acc15144a2afec889370612cca66`
- C9: `cursor/linux-confine-e156` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`

`JPK_C0_PR`, `JPK_C0_REF`, and `JPK_C0_SHA` select the guard source. A PR
ref records the fetched HEAD unless `JPK_C0_SHA` is also set.

The ABI probe is `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
`uname -r` is not the ABI.

## What the kit records

From one run it writes:

- `uname -r` and `uname -m`
- Landlock ABI
- per-right availability: truncate, ioctl_dev, net bind, net connect,
  scope signal, scope abstract unix
- seccomp availability and `AUDIT_ARCH_*`
- unprivileged user, PID, and mount namespace availability
- the sysctls that gate those namespaces
- the capability bounding set

It then prints two tables for did, wallet, and model:

1. A policy oracle (`decide.py`) that copies `fail_closed_linux` at
   `2c70a0d8`. It is labeled as an oracle, not as `fcl-launch`.
2. The real #307 guard: `fcl-launch` of a static stand-in for each of
   `did-provider`, `wallet-provider`, and `model-provider`.

The oracle uses #307's public functions. The extra ABI 5 floor prints
`Landlock ABI N is below the required 5`. The per-right floor prints
`this kernel's Landlock ABI N cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)`.
#307 trusts the ABI number. A lying ABI 5 with ABI 1 rights therefore
launches under `per_right`; the kit also records the measured rights.

`CAP_SETPCAP` is bit 8.

## Bounds

The script runs as the calling user. It keeps every write, clone, cargo
home, and build directory under `~/flint-elastos-test`. Cargo and gcc use
four jobs. A `MemAvailable` reading below 1 GiB stops the run. The script
leaves the rest of the board alone.

## Checks that run off the board

```bash
bash lab/jetson-proof-kit/tests/test_guards.sh
bash lab/jetson-proof-kit/tests/test_decisions.sh
bash lab/jetson-proof-kit/falsify.sh
```

The first command covers the path guard, a planted path outside the
folder, the memory floor, the C0 source selector, launch classification,
and the committed Jetson rows. The second command feeds simulated kernel
answers into the oracle and checks #307's reason text. The third command
plants bugs on copies. The working tree stays unchanged.
