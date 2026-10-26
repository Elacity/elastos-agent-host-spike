# Adversarial review of PR #296 aarch64 qemu-system evidence

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

```text
Lane:         lab/review-296-aarch64-guest
Branch / PR:  cursor/review-296-aarch64-guest-f1ba
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         de819640b12ba809884fc5ba1b2c408eb2878e9a
Parent:       5e0b11ac4a0070d0c7ff4115f3251e1148c89fab
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #296 is Claude family)
Date:         26 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The new aarch64 evidence is real when you run the author's script from
`/workspace`. It is a real aarch64 Linux kernel, under qemu-system TCG,
not qemu-user. The suites that ran as guest uid 1000 printed
`enforced ... uid=0` because the launcher maps that uid to 0 inside an
unprivileged user namespace. That is expected. The guest run stays
unprivileged.

The wait for `errno=13` after `enforced` does not count a timeout as a
pass. The launcher does not print the exec errno line before `execve`.
The wait is a bit loose: it accepts any `errno=13` on that spawn and
then returns a fixed string.

The host script always exits 0 after a labeled boot. A first rerun from
a `/tmp` worktree failed almost every launch test, and the host still
exited 0. `RESULTS.txt` is a write-up, not a file the guest writes.
The per-suite logs are live rust output. They are not a hardcoded PASS.

This proves C9 on an emulated aarch64 CPU with Alpine virt 6.18. It does
not prove a Jetson or any other real ARM board.

**VERDICT: PASS** for the emulated-aarch64 C9 claim on this head. Keep
native aarch64 / Jetson as NOT RUN. Keep `make-char` / `make-block` as
NOT PROVEN. Keep `socketpair(AF_UNIX)` as the named C9 departure.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| elf 6/0, aarch64 2/0/1 ignored, confine 25/0, providers 4/0 | **HOLDS** on `/workspace` | Fresh `summary.txt`: elf `6 passed; 0 failed; 0 ignored`; aarch64 `2 passed; 0 failed; 1 ignored`; confine `25 passed; 0 failed; 0 ignored`; providers `4 passed; 0 failed; 0 ignored`. Times differ from the committed log (0.53s / 0.03s / 2.88s / 13.00s vs 0.51s / 0.04s / 2.78s / 12.54s). |
| Guest kernel is aarch64, ABI 7, not qemu-user | **HOLDS** | Console: `Booting Linux on physical CPU 0x0000000000`, `Linux version 6.18.58-0-virt`, `uname.machine=aarch64`, `landlock_create_ruleset nr=444 ret=7`, `landlock_abi=7`. qemu is `8.2.2` with `-accel tcg`. The ignored aarch64 test is the qemu-user / host-kernel row. |
| Binaries under test are aarch64 ELF from this head | **HOLDS** | `file` and `e_machine=183` on guest-bins, `lc-setup*`, `lc-probe`, and the three provider debug binaries. `vmlinuz-virt` sha256 `d1876369...` matches the committed stamp. See `BINARIES.txt`. |
| Suites ran as uid 1000; `enforced uid=0` is user-ns mapping | **HOLDS** | `run-c9.sh` prints `uid=1000 gid=1000`. `init.sh` drops to tester 1000 (`su` or `run-as-tester`). `setup.c` does `unshare(CLONE_NEWUSER)` and writes `0 <uid> 1` into `uid_map` / `gid_map`, then requires `geteuid()==0` before printing `enforced`. The printed uid 0 is inside that namespace. Guest root only starts PID 1. |
| The run is unprivileged on the guest | **HOLDS** | No `sudo` in the suites. Tester has no `CAP_MKNOD`. Confine still prints `NOT PROVEN` for unconfined make-char / make-block (`EPERM`). |
| Six in-guest plants CAUGHT | **HOLDS** | `F-LC-CAPBND`, `F-LC-BLOCK`, `F-LC-STORAGE`, `F-LC-PROVIDER-SOCKET`, `F-LC-SOCKET`, `F-LC-ANY-ERRNO` each wrote `CAUGHT`. Host-only plants stay `NOT_RUN`. |
| Wait for exec `errno=13` can mask a real failure | **HOLDS** that timeout is a fail; **WEAK** on substring + hardcoded reason | After 5s the test still `assert!`s `errno=13`. Missing line fails. `setup.c` prints `enforced` before `execve` and the exec errno line only after `execve` returns. The wait matches any `errno=13` on that stderr, then returns a fixed string instead of the line it saw. A pre-exec `refuse_errno(..., 13)` would satisfy the wait. That is a harness looseness, not a timeout-as-pass. |
| Evidence files match a fresh run and contain no hardcoded PASS | **HOLDS** for the machine logs; **WEAK** for `RESULTS.txt` and the host wrapper | Fresh suite logs match the committed logs except timings. `RESULTS.txt` is not written by `run-c9.sh` or `run-aarch64-guest.sh`; a wiped evidence dir does not recreate it. Status `PASS` is written only when the rust binary exits 0. |
| Host script fail-closes on a bad guest | **WEAK** | `run-aarch64-guest.sh` exits 0 after a labeled boot. It does not read `*.status`. It does not wipe old evidence. The `/tmp` worktree rerun had `guest_exit=1` and host `EXIT=0`. |
| Script reproduces from any checkout path | **WEAK** | Helpers and `CARGO_MANIFEST_DIR` bake the host path. Capsules are installed at `/workspace/capsules`. `init.sh` mounts tmpfs on `/tmp`. A worktree under `/tmp/wt/...` hid those helpers: elf 4/2, confine 2/23, providers 0/4, plants `NOT RUN`. Author evidence used `repo=/workspace`. |
| Review plants: drop seccomp, widen `/`, skip netns | **HOLDS** as catches, with one qemu-shaped gap | `M-R-DROP-SECCOMP` CAUGHT (`socket` became `ok`). `M-R-WIDE-ROOT` failed the standing test: `outside-read` became `ok` (the plant helper grepped the denied reason and said UNEXPECTED; the log is a catch). `M-R-SKIP-NETNS` SURVIVED on the author's lo-only qemu (`netns=lo` still). With a review-only `dummy0`, the same plant is CAUGHT (`netns=host`) and standing confine stays 25/0. |
| This proves C9 on real ARM hardware | **does not hold** | TCG emulated CPU. Alpine virt kernel, not a board kernel. Debug gnu binaries, not the board's shipped link. No KVM, no Jetson devices, no `CAP_MKNOD`. |

## uid=0 versus uid 1000

PID 1 is root. It enables unprivileged user namespaces, then runs
`/usr/local/bin/run-c9.sh` as tester uid 1000. The rust suites therefore
start as 1000.

The launcher then creates its own user namespace and maps that 1000 to
namespace uid 0:

```c
unshare(CLONE_NEWUSER);
write(setgroups, "deny");
write(uid_map, "0 <guest-uid> 1");
write(gid_map, "0 <guest-gid> 1");
```

`geteuid()` inside that namespace is 0, so the `enforced` line says
`uid=0 caps=empty`. From the guest's initial user namespace the process
is still the tester mapping. Empty capabilities and `no_new_privs=1`
stay. This is not a hidden root launch of the suites.

## Wait for `errno=13`

`spawn_provider` returns as soon as it sees `enforced`, and that line is
printed before `execve`. On a slow TCG cpu the later
`exec of PROVIDER_EXECUTABLE failed errno=13` can arrive after the first
stderr read. The 5 second poll fixes that race.

Timeout is a fail: the `assert!(err.contains("errno=13"))` still runs.

The launcher does not forge the exec line before `execve`. It forges
nothing; it prints `enforced`, calls `execve`, and only then prints
`errno=%d`.

What remains weak: the poll looks for the substring `errno=13` anywhere,
then the function returns a constant reason. Callers never check that
the line was the exec line.

## Fresh rerun

```text
# 1. Path-locked failure (review worktree under /tmp)
# guest_exit=1, host EXIT=0
elf      4 passed; 2 failed
confine  2 passed; 23 failed   # cannot start launcher: No such file
providers 0 passed; 4 failed
plants   NOT RUN (helper_dir empty)

# 2. Author path, unmodified script
cd /workspace   # detached de819640
lab/linux-confine/run-aarch64-guest.sh full
# guest_exit=0, host EXIT=0
# host-context head=de819640b12ba809884fc5ba1b2c408eb2878e9a
# repo=/workspace
# qemu=QEMU emulator version 8.2.2
# Guest: Linux 6.18.58-0-virt aarch64, landlock_abi=7, uid=1000
```

| suite | this rerun | committed evidence |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.53s | 6 / 0 / 0 in 0.51s |
| aarch64 | 2 / 0 / 1 in 0.03s | 2 / 0 / 1 in 0.04s |
| confine | 25 / 0 / 0 in 2.88s | 25 / 0 / 0 in 2.78s |
| providers | 4 / 0 / 0 in 13.00s | 4 / 0 / 0 in 12.54s |
| F-LC-* in-guest | 6 CAUGHT | 6 CAUGHT |

`enforced abi=7 uid=0 caps=empty nnp=1 netns=lo storage_rights=0x41be`
on did, wallet, and model. CapBnd on did-provider is
`0000000000000000`.

Committed `RESULTS.txt` and `qemu-smoke-abi.txt` did not come back after
the evidence dir was wiped. They are session write-ups, not guest
output. The machine files (`summary.txt`, `*.txt` suite logs, `*.status`)
are produced live.

## Review plants

Standing sources were not pushed. Plants were compiled into
`guest-plants/` and swapped over `lc-setup` inside the guest.

| id | plant | on author's qemu (lo only) | with review-only dummy0 |
| --- | --- | --- | --- |
| M-R-DROP-SECCOMP | skip both seccomp installs (`if (0)`) | **CAUGHT** — `socket result=ok` | CAUGHT |
| M-R-WIDE-ROOT | `add_rule("/", handled_fs())` | standing test **failed**: `outside-read result=ok`. Helper said UNEXPECTED because it grepped the denied reason string. Treat as **CAUGHT**. | same |
| M-R-SKIP-NETNS | skip `unshare(CLONE_NEWNET)` | **SURVIVED** — `netns=lo` | **CAUGHT** — `netns=host`; standing confine still 25/0 |

The author's qemu command has no NIC. `netns=lo` is true for the guest
itself. Skip-netns is not visible until another interface exists.
The launcher netns still works: with `dummy0 lo` present, the standing
rows stay `netns=lo`.

The six author plants were CAUGHT again on the same guest boots.

## What this proves, and what hardware still has to do

This head proves the C9 rows on a real aarch64 kernel (Alpine virt
6.18.58, Landlock ABI 7) running on an emulated CPU (qemu-system 8.2.2
TCG). Syscall numbers, ELF machine, ioctl-dev, CapBnd 0, and the six
in-guest plants are that kernel's.

It does not prove:

- a Jetson or any other aarch64 board
- that board's kernel, modules, or Landlock ABI
- binaries linked the way that board ships them (musl vs gnu, search
  paths, CPU features)
- KVM / hardware virtualization instead of TCG
- `make-char` / `make-block` as positive controls (`CAP_MKNOD`)
- closing the named `socketpair(AF_UNIX)` departure

A production ARM claim still needs the same suites on that board,
kernel >= 6.7 so ABI >= 5 can express `IOCTL_DEV`, against the binaries
that board actually runs.

## Principles

- 3 No ambient authority: the guest rows still deny outside read/write,
  socket, unbound exec, and host signal when the launcher is intact.
- 5 Small trusted core: this review is lab evidence only.
- 11 Fail closed: Landlock / seccomp / userns absence still refuse the
  start on this kernel. The host wrapper does not fail closed.
- 12 Docs, code, tests, and operations must agree: label the result
  `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.
  `RESULTS.txt` is a note, not a guest artifact.

## Questions

none
