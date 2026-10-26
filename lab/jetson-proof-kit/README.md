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

To fetch the current #307 head instead of the pinned commit (the per-right
floor work):

```bash
cd ~/flint-elastos-test && JPK_C0_PR=307 ./run-on-jetson.sh
```

The script writes `~/flint-elastos-test/evidence.txt`. Each row is `PASS`,
`REFUSED` with a reason, or `NOT RUN`.

Set `JPK_REMOTE` when git should fetch the draft branches from a clone the
board already has. The default pins are:

- C0: `cursor/fail-closed-linux-0b95` at `129fdc98428c9029b328976511478c46ebe765a6`
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

It then prints a table. For each provider (did, wallet, model) and each
floor (single ABI 5, per-right) it says LAUNCH or REFUSE and why. The
single floor uses the ABI number. The per-right floor uses the measured
truncate and ioctl_dev bits. Both also need an unprivileged user
namespace, seccomp, and a droppable bounding set.

## What a refusal means

The table is computed from the measured facts. It does not depend on
which C0 commit was fetched. The fetched C0 and C9 binaries still run
their own guards; those rows are the binary's own text.

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
folder, the memory floor, the C0 source selector, and the committed
Jetson rows. The second command feeds simulated kernel answers into the
decision table. The third command plants three bugs on copies: an
outside path that is accepted, a missing memory check, and a
mis-reported ABI. All three plants are caught. The working tree stays
unchanged.
