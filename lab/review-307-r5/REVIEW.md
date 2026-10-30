# Independent adversarial review r5 of C0 (#307)

Independent adversarial review r5 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux launch) at `747cda4f`.

Draft only. Do not merge this review PR. This folder is the only tree
this session writes. `lab/fail-closed-linux/` was left as the author
wrote it. Branch `cursor/fail-closed-linux-0b95` was not pushed. The
public Elacity repo was not touched.

```text
Lane:           lab/review-307-r5
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Head:           747cda4f0f2dfb5953baad1c62c44be1a0d84e71
Parent:         dc5fe676e8ad13e5882871a27b9f2dd166780bf5
Tree:           /tmp/wt-307-r5/candidate  (detached worktree)
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351),
                Landlock ABI 6, uid 1000
Aarch64:        qemu-system TCG, Alpine virt 6.18.58, ABI 7
                label: emulated CPU. Never native ARM.
Jetson stand-in: qemu-system TCG, Alpine virt 5.15.208, ABI 1
                label: emulated 5.15 kernel. Not a Jetson board.
```

## Plain English

The exact r4 leftovers are closed on this Linux x86_64 ABI 6 host.
`execveat` and `memfd_create(MFD_EXEC)` return EPERM. A pre-confine
pty on stdin is replaced with `/dev/null`, so `TIOCGWINSZ` and
`TIOCSTI` fail with ENOTTY. After start the probe has only fds 0, 1
and 2. The post-restrict self-test really runs write-outside,
truncate, ioctl, memfd `execveat`, REFER, and make_*.

The author's stronger sentence does not hold. A memfd created
*without* `MFD_EXEC`, then `fchmod` and `execve("/proc/self/fd/N")`,
runs a second image. That is the same class of hole r4 named, on a
path the second filter leaves open. Pathname `execve` of the granted
binary itself works and does *not* drop the second filter. Filters
persist across that exec.

Claimed host counts match: **lib 9, simulated 21, real_kernel 28**,
all green, none ignored. `falsify.py` is **33/33 caught**, control
survived with **58 tests**. Independent replant of F36 and F37 on
copies made those named tests fail again.

On an **emulated CPU** aarch64 guest (kernel 6.18, ABI 7): lib 9 and
simulated 21 pass. real_kernel is **26 passed, 2 failed**. The two
failures are the extra-right rows that assume the host ABI is below
7. The r4 leftover rows on that guest (`real_memfd_second_image`,
`real_stdin_pty`, confined layers) pass.

On an **emulated 5.15 kernel** (ABI 1, not Jetson): launch refuses
did, wallet and model. Each refusal names `truncate` (needs ABI 3)
and `ioctl_dev` (needs ABI 5) and exits 71.

A real Jetson board is still required. This guest is Alpine virt
5.15.208, not tegra.

**VERDICT: FIX.** The claimed r4 mechanisms hold. A memfd second
image still runs.

## Re-run of the claimed suites

From `/tmp/wt-307-r5/candidate/lab/fail-closed-linux` at `747cda4f`:

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          9 passed; 0 failed; 0 ignored
  simulated   21 passed; 0 failed; 0 ignored
  real_kernel 28 passed; 0 failed; 0 ignored
python3 falsify.py --jobs 4
  falsifiers: 33/33 caught; controls: 1/1 survived
  C00-noop-control: 58 tests passed
  F36-memfd-execveat CAUGHT
  F37-stdio-pty CAUGHT
```

Evidence: `evidence/official-suite.txt`, `evidence/falsify.txt`.

The author's "lib 9 / simulated 21 / real_kernel 28 / 33/33 +
control" holds on this host. The control suite is 58 tests
(9 + 21 + 28).

## Verdicts on the claimed r4 leftovers

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 9, simulated 21, real_kernel 28, 0 ignored | **HOLDS** on x86_64 ABI 6 | `evidence/official-suite.txt` |
| C0-T2 | falsify 33/33 caught, control survived | **HOLDS** (control 58 tests) | `evidence/falsify.txt` |
| R4-1 | second seccomp filter: `execveat` and `memfd_create(MFD_EXEC)` return EPERM | **HOLDS** for those two calls | live `memfd_execveat errno=1`; `memfd_exec_create errno=1`; F36 CAUGHT; strace `execveat(... AT_EMPTY_PATH) = -1 EPERM`; two `seccomp` loads (len 57 then len 13) |
| R4-2 | terminal on fd 0/1/2 replaced with `/dev/null` | **HOLDS** | live stdin pty: `ioctl_fd_0 errno=25`, `tiocsti_fd_0 errno=25`. F37 CAUGHT: planted tree prints `stdin_tty=1` and `stdin_ioctl ok` |
| R4-3 | only fds 0-2 after start | **HOLDS** | hunter `listfds`: fd 0, 1, 2 only. Identity pipe is close-on-exec |
| R4-4 | self-test covers execveat memfd, REFER, make_* | **HOLDS** for the ops it reaches | strace: write-open `EACCES`, truncate `EACCES`, ioctl `EACCES`, `execveat` `EPERM`, rename across `_a`/`_b`, symlink `EACCES` |

## Re-plant of F36 and F37

Copies only. The #307 worktree was left alone. Each plant is the
official mutant text, applied by this session's `replant.py`.

| Plant | Named test | This session |
| --- | --- | --- |
| F36 skip `install_no_exec_filter` | `real_memfd_second_image_is_refused` | **CAUGHT** |
| F37 skip `sanitize_stdio` | `real_stdin_pty_is_not_a_terminal` | **CAUGHT**. Planted run: `stdin_tty=1`, `stdin_ioctl ok` |

Evidence: `evidence/replant.txt`. Official `falsify.py` also caught
both in the 33/33 run.

## r4 hunts, replanted

Live against the built `fcl-launch` at this head.

| Attack | Result | Verdict |
| --- | --- | --- |
| `execve` of a second static file outside the root | `errno=13`. Exe stays hunter | path exec **denied** |
| Write a payload under storage, then `execve` | `errno=13` | storage exec **denied** |
| Same path, new inode (rename over the running file) | inode 425119 → 425259. `errno=13`. Exe is `(deleted)` | swapped inode **denied** |
| Host bind-mount | `mount` errno 1 | **NOT RUN** on this uid |
| memfd + `execveat(AT_EMPTY_PATH)` | `memfd_execveat errno=1`. No payload line | **denied** (r4 hole closed) |
| Identity fd | only fd 0, 1, 2 | leftover pipe **gone** |
| Stdin is a pre-confine pty | `ioctl_fd_0 errno=25`, `tiocsti_fd_0 errno=25` | **denied** (r4 hole closed) |

## New hunts

### Re-exec of the granted binary itself

Pathname `execve` of the granted hunter path ran. The next image
printed `after_reexec pid=2`. Then `memfd_create(MFD_EXEC)` returned
EPERM and `execveat` of a no-exec memfd returned EPERM. `/proc/exe`
stayed the hunter. Ioctl on stdin stayed ENOTTY.

So: a later `execve` of the granted path resets user-space state
(argv, memory). It does **not** drop the stacked seccomp filters,
Landlock, or the namespace. The second filter persists across exec.

### memfd without `MFD_EXEC`, then `/proc/self/fd/N`

`memfd_create` with flags 0 succeeded. `fchmod` 0755 succeeded.
`execve("/proc/self/fd/N")` ran the payload. Next stdout line:
`payload pid=2`.

This is a second image after start. Seccomp denies `execveat` and
`MFD_EXEC` create. It leaves pathname `execve` allowed. Landlock
EXECUTE did not stop the procfs magic-link. The author's claim that
a memfd second image cannot run is false.

### `shm_open` + `/dev/shm` exec

`shm_open` returned EACCES 13. Storage has no grant on `/dev/shm`.
No second image.

### ELF written into the granted storage dir, then `execve`

Same as the r4 storage hunt: `execve` `errno=13`. Storage has write
and no EXECUTE.

### `ptrace` / `process_vm_writev` / `io_uring_setup`

All three returned EPERM 1. They are on the first deny-list.

### fd 0-2 as a socket or a pipe

A pipe on stdin stays a pipe (`fd 0 kind=pipe`). A Unix socket on
stdin stays a socket. From the host end, `SCM_RIGHTS` delivered a
new fd (fd 3) into the confined process, and a `read` of a host
file succeeded (12 bytes). Sanitize only replaces a terminal.
Inherited 0-2 can still carry extra rights.

This is not a fail-open launch. It is leftover ambient authority
through stdio.

### ioctl on `/dev/null`

`TIOCGWINSZ` and `TIOCSTI` on the replaced stdin returned ENOTTY 25.

## aarch64 execution (emulated CPU)

Reused the qemu-system aarch64 TCG guest from PR #296 (Alpine virt
kernel 6.18.58, `-accel tcg`, `-cpu max`). Label printed by the
guest:

```text
LABEL=aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
native=0
jetson=0
emulated_cpu=1
Linux (none) 6.18.58-0-virt ... aarch64 Linux
landlock_abi=7
```

Never native ARM. Never Jetson.

The author's `build.rs` skips the static probe when TARGET != HOST,
and the probe uses `*const i8` for paths. A raw aarch64 probe build
fails on `c_char` signedness and then links with the host `cc`. This
session patched a **copy** only (`c_char` + `aarch64-linux-gnu-gcc`)
so the suites could actually run. The #307 tree was not edited.

| Suite | Passed | Failed | Ignored |
| --- | --- | --- | --- |
| lib | 9 | 0 | 0 |
| simulated | 21 | 0 | 0 |
| real_kernel | 26 | 2 | 0 |

The two real_kernel failures are
`real_per_right_floor_refuses_on_this_kernel` and
`real_extra_floor_still_names_the_missing_right`. Both require
`host ABI < 7`. This guest reports ABI 7, so `future_fs` is no
longer future. The r4 leftover rows on this guest passed:
`real_memfd_second_image_is_refused`,
`real_stdin_pty_is_not_a_terminal`,
`real_confined_provider_has_every_layer`.

Evidence: `evidence/aarch64-qemu-system-6.18/`.

## Jetson ABI-1 stand-in (emulated 5.15 kernel)

Booted Alpine virt **5.15.208-0-virt** under the same qemu-system
TCG. Label:

```text
LABEL=emulated 5.15 kernel under qemu-system TCG (not Jetson)
landlock_abi=1
```

`fcl-launch` for did, wallet and model each exited 71:

```text
fail-closed-linux refused to start did-provider: layer landlock, step abi_floor: this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5); the provider was not started
```

Same text for wallet-provider and model-provider.

This is an emulated 5.15 kernel, not a Jetson. It does not prove
tegra 5.15.148, JetPack LSM config, or real provider binaries.

Evidence: `evidence/aarch64-qemu-5.15/`.

## Exact counts per platform

| Platform | lib | simulated | real_kernel | notes |
| --- | --- | --- | --- | --- |
| Linux x86_64, kernel 6.12.94+, ABI 6 | 9 | 21 | 28 | official claim holds |
| aarch64 emulated CPU, kernel 6.18.58, ABI 7 | 9 | 21 | 26 pass / 2 fail | extra-right rows assume ABI < 7 |
| emulated 5.15.208 kernel, ABI 1 | n/a | n/a | n/a | 3/3 providers refuse, name truncate / ioctl_dev |
| Real Jetson | NOT RUN | NOT RUN | NOT RUN | still needed |

Falsify on the host only: 33/33 caught, control 58 tests.

## What still needs a real Jetson

- The tegra kernel (typically 5.15.148-tegra), not Alpine virt 5.15.208
- Whether Landlock is on at all on that board (ABI 1 vs ENOSYS)
- Real did / wallet / model binaries and their loader/library grants
- Board userns / seccomp / cgroup policy
- The procfd second-image hunt on that kernel (`vm.memfd_noexec` may differ)

The emulated 5.15 guest is a stand-in for the ABI-1 refusal text only.

## Residuals

1. **Memfd second image via `/proc/self/fd/N`.** `execveat` and
   `MFD_EXEC` create are denied. Pathname `execve` of a memfd is not.
   This is the FIX.
2. **Granted-path re-exec** resets user space and keeps the filters.
   Named, not a fail-open.
3. **Stdio 0-2 can be a pipe or a socket.** `SCM_RIGHTS` can import
   a host fd. Sanitize only replaces a tty.
4. **Bind-mount of the executable** was EPERM on this uid.
5. **real_kernel extra-right rows** assume ABI < 7. They fail on
   kernel 6.18 ABI 7.
6. **Author tree does not cross-build the static probe.** `cargo
   check --target aarch64` skips it. A guest run needs a copy patch.
7. **Network Landlock and `LANDLOCK_SCOPE_SIGNAL`** stay NOT COVERED
   by the self-test, as the author said.

## This folder

| Path | Why |
| --- | --- |
| `REVIEW.md` | this report |
| `README.md` | pointer |
| `attack.py` | live hunts against the built `fcl-launch` |
| `replant.py` | independent F36 / F37 plants on copies |
| `run-aarch64-guest.sh` | qemu-system TCG guest (emulated CPU / emulated 5.15) |
| `standins/hunter.c`, `payload.c` | static stand-ins |
| `evidence/` | official suite, falsify, replant, attacks, both guests |

```bash
lab/review-307-r5/run.sh
```

Needs `FCL_SRC` (default `/tmp/wt-307-r5/candidate/lab/fail-closed-linux`)
and that tree's built `fcl-launch`.

## Principles

- 3: after start the process keeps only fds 0-2. Those fds can still
  be a host pipe or a socket that imports extra fds. A memfd image
  can replace the granted binary.
- 11: a failed second filter or a failed stdio replace refuses the
  launch. A later pathname exec of a memfd is outside that start rule.
- 12: the README host counts (9 / 21 / 28, falsify 33/33) match this
  run. The aarch64 real_kernel count does not: 26/28 on ABI 7.

DeepSeek: none.

## Next

Keep #307 draft. Close the procfd/`execve` memfd path (deny pathname
exec of anonymous files, or deny `execve` after start except the
granted inode). Say what happens to inherited sockets on 0-2. Bump
the extra-right tests so ABI 7 is not a false fail. Run the same
rows on a real Jetson board.

**VERDICT: FIX** at `747cda4f`. The claimed r4 calls are denied. A
memfd second image still runs.
