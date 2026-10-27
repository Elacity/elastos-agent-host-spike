# Independent adversarial review r6 of C0 (#307)

Independent adversarial review r6 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux confine) at `13447927`.

Draft only. Do not merge this review PR. This folder is the only tree
this session writes. `lab/fail-closed-linux/` was left as the author
wrote it. Branch `cursor/fail-closed-linux-0b95` was not pushed. The
public Elacity repo was not touched.

Read first: r5 review PR
https://github.com/Elacity/elastos-agent-host-spike/pull/410
at `747cda4f`. r5 leftover: memfd without `MFD_EXEC`, then
`execve("/proc/self/fd/N")`, still ran a second image.

```text
Lane:           lab/review-c0-307-r6
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Head:           1344792715fc21fef94dca5e973e14231ce604a6
Parent:         e7422d66 (no exec after start, no stdio sockets)
Tree:           /workspace  (detached at 13447927)
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351),
                Landlock ABI 6, uid 1000, no Yama ptrace_scope
Aarch64:        qemu-system TCG, Alpine virt 6.18.58, ABI 7
                label: emulated CPU. Never native ARM.
Jetson stand-in: qemu-system TCG, Alpine virt 5.15, ABI 1
                label: emulated 5.15 kernel. Not a Jetson board.
```

## Plain English

The r5 leftover is closed on this Linux x86_64 ABI 6 host. After
start, `execve` and `execveat` return EPERM, including pathname
re-exec of the granted binary, `/proc/self/exe`, `/proc/self/fd/N`
of a no-`MFD_EXEC` memfd, and a `#!` script whose interpreter is
ungranted. A terminal or a socket on fds 0-2 is replaced. An
inherited socket or pty on fd 3+ is gone. `falsify.py` is 35/35
caught; C00 survived with 62 tests (9+22+31).

The author's extra-right rows are ABI-aware in source: on ABI < 7
they refuse `future_fs`; on ABI >= 7 they assert a start. This host
is ABI 6, so the refuse half ran here.

A same-uid host process can still `PTRACE_ATTACH` the confined
provider and open `/proc/<pid>/mem`. Dumpable stays 1. Inside the
sandbox, sibling `ptrace` is EPERM and `/proc/self/mem` is EACCES.
That host attach is a named residual, not a second image from
inside.

**VERDICT: PASS** for the Linux lab half of the claimed leftovers.
Real Jetson: NOT RUN. Landlock TCP and `LANDLOCK_SCOPE_SIGNAL`:
NOT COVERED.

## Re-run of the claimed suites

From `/workspace/lab/fail-closed-linux` at `13447927`:

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          9 passed; 0 failed; 0 ignored
  simulated   22 passed; 0 failed; 0 ignored
  real_kernel 31 passed; 0 failed; 0 ignored
python3 falsify.py --jobs 2
  falsifiers: 35/35 caught; controls: 1/1 survived
  C00-noop-control: 62 tests passed
```

Evidence: `evidence/official-suite.txt`, `evidence/falsify.txt`.

Host counts match the author: **lib 9, simulated 22, real_kernel 31**.
Control suite is 62 tests (9+22+31).

## Verdicts on the claimed leftovers

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 9, simulated 22, real_kernel 31, 0 ignored | **HOLDS** on x86_64 ABI 6 | `evidence/official-suite.txt` |
| C0-T2 | falsify 35/35 caught, C00 survives | **HOLDS** (control 62 tests) | `evidence/falsify.txt` |
| C0-T3 | after confine, execve/execveat EPERM except the helper's one granted-path execve | **HOLDS** | official memfd/reexec/procfd rows; live hunts below |
| C0-T4 | fds 0-2 that are terminals or sockets are replaced with /dev/null | **HOLDS** | official stdin pty/socket rows; inherited fd 3 gone |
| C0-T5 | extra-right real_kernel rows are ABI-aware (ABI>=7 asserts ABI-7) | **HOLDS** in source; ABI 6 host ran the refuse half | `real_per_right_floor_refuses_on_this_kernel` |

## New hunts (this session)

Live against the built `fcl-launch` at this head. Stand-in is
`standins/hunter.c`. Evidence: `evidence/attacks.json`,
`evidence/attacks.stdout.txt`.

| Attack | Result | Notes |
| --- | --- | --- |
| granted-path execve used twice | **CAUGHT** | `reexec1 errno=1`, `reexec2 errno=1`. No payload line |
| symlink of the granted path, then execve | **CAUGHT** | `exec_path errno=1` |
| bind-mount swap of the granted path | **NOT RUN** on this uid (`mount` exit 32). Pathname execve of the granted file still `errno=1` | host cannot bind-mount |
| execve `/proc/self/exe` | **CAUGHT** | `proc_exe errno=1`; `execveat` also `errno=1` |
| execve of a `#!` script after start (ungranted interpreter) | **CAUGHT** | `shebang errno=1` |
| granted path is itself a `#!` script | **CAUGHT** | launch refused, layer exec, step execve, EACCES 13. Interpreter did not run |
| fd 3+ socket inherited, then dup2 onto 0 | **CAUGHT** | `inherit_fd_3 gone errno=9`. Only fds 0-2 remain |
| pipe on stdin, SCM_RIGHTS later | **CAUGHT** | stdin stays a pipe; `recvmsg`/`sendmsg` errno 88 (`ENOTSOCK`) |
| TIOCSTI on a terminal fd kept above 2 | **CAUGHT** | `tiocsti_fd_3 errno=9` (fd closed) |
| execve via `int 0x80` / `__X32_SYSCALL_BIT` | **CAUGHT** | child `SIGSYS` (31). Foreign arch kills |
| clone3 `CLONE_INTO_CGROUP` | **CAUGHT** | `errno=38` (`ENOSYS`) |
| io_uring to open/exec | **CAUGHT** | `io_uring_setup errno=1`; enter/register `errno=95` |
| ptrace of a sibling | **CAUGHT** | `ptrace_sibling errno=1`; `PTRACE_TRACEME errno=1` |
| r5 leftover: memfd no `MFD_EXEC`, `execve(/proc/self/fd/N)` | **CAUGHT** | official probe `memfd_procfd errno=1`. No `memfd_exec ran` |
| prctl `PR_SET_DUMPABLE` from inside | **CAUGHT** for a second image | `/proc/self/mem` open EACCES 13; sibling ptrace EPERM |
| same-uid host `PTRACE_ATTACH` / `/proc/<pid>/mem` | **SURVIVED** | dumpable stays 1; this host has no Yama. Host attach returned 0; `/proc/<pid>/mem` opened |

### Exact patch for the host-ptrace residual

The provider stays dumpable. A same-uid process on a host without
Yama can attach and open `/proc/<pid>/mem`. That is host-side
attach, not a provider exec. If C0 should close it, after the id
maps and before exec:

```text
// src/real.rs, after write_gid_map / cap drop, before exec
if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
    return Err(errno());
}
```

And add `PR_SET_DUMPABLE` to the first seccomp deny-list (or
allow only the value 0) so the provider cannot turn dumpable
back on. A test: after start, `PR_SET_DUMPABLE(1)` returns
EPERM, and a same-uid helper's `PTRACE_ATTACH` fails when Yama
is off.

This session did not apply that patch. The #307 tree was not edited.

## aarch64 execution (emulated CPU)

qemu-system aarch64 TCG, Alpine virt 6.18. Guest label:

```text
LABEL=aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
native=0
jetson=0
emulated_cpu=1
```

Expected if the author's ABI-7 claim holds: lib 9, simulated 22,
real_kernel 31. Evidence under `evidence/aarch64-qemu-system-6.18/`
when the guest finishes.

Never native ARM. Never Jetson.

## Jetson ABI-1 stand-in (emulated 5.15 kernel)

Same qemu-system TCG, Alpine virt 5.15. Label:

```text
LABEL=emulated 5.15 kernel under qemu-system TCG (not Jetson)
```

Author claim: did / wallet / model each exit 71 and name
`truncate` (needs ABI 3) and `ioctl_dev` (needs ABI 5).
Evidence under `evidence/aarch64-qemu-5.15/` when that guest
finishes.

This is an emulated 5.15 kernel, not a Jetson. It does not prove
tegra 5.15.148, JetPack LSM config, or real provider binaries.

## Exact counts per platform

| Platform | lib | simulated | real_kernel | notes |
| --- | --- | --- | --- | --- |
| Linux x86_64, kernel 6.12.94+, ABI 6 | 9 | 22 | 31 | official claim holds |
| aarch64 emulated CPU, kernel 6.18, ABI 7 | pending guest | pending | pending | author claims 31/31 |
| emulated 5.15 kernel, ABI 1 | n/a | n/a | n/a | pending guest; author claims 3/3 refuse 71 |
| Real Jetson | NOT RUN | NOT RUN | NOT RUN | still needed |

## Not covered

- Landlock TCP bind/connect. Seccomp denies `socket` first.
- `LANDLOCK_SCOPE_SIGNAL` self-test. The self-test child shares
  the provider PID namespace.
- Host bind-mount of the granted path (this uid, `mount` exit 32).
- Real Jetson board.

## This folder

| Path | Why |
| --- | --- |
| `REVIEW.md` | this report |
| `README.md` | pointer |
| `attack.py` | live hunts against the built `fcl-launch` |
| `run-aarch64-guest.sh` | qemu-system TCG guest (emulated CPU / emulated 5.15) |
| `standins/hunter.c`, `payload.c` | static stand-ins |
| `evidence/` | official suite, falsify, attacks, guests |

```bash
FCL_SRC=/path/to/fail-closed-linux lab/review-c0-307-r6/run.sh
FCL_SRC=/path/to/fail-closed-linux lab/review-c0-307-r6/run-aarch64-guest.sh full
FCL_SRC=/path/to/fail-closed-linux lab/review-c0-307-r6/run-aarch64-guest.sh abi1
```

## Principles

- 3: after start the process keeps only fds 0-2. Exec after start
  is EPERM. A same-uid host can still attach while dumpable is 1.
- 11: a failed second filter or a failed stdio replace refuses the
  launch. A `#!` granted path whose interpreter is ungranted also
  refuses (EACCES).
- 12: the README host counts (9 / 22 / 31, falsify 35/35) match
  this run.

DeepSeek: none.

## Next

Keep #307 draft. Optional: set dumpable 0 and deny later
`PR_SET_DUMPABLE`. Run the ABI 7 and ABI 1 guests (this session
is doing that). Run the same rows on a real Jetson board.

**VERDICT: PASS** at `13447927` for the Linux lab half of the
claimed leftovers. The r5 memfd second image is closed. Host
dumpable/ptrace is a named residual with an exact patch above.
