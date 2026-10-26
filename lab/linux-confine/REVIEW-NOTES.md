# Review notes for @irzhyran

This is lab code under `lab/linux-confine/`. It does not change the Runtime launcher, the provider sources, or the macOS profiles. The profiles in `capsules/*/confine.sb` and their `declared-rights.json` files stay the oracle. The lab reads them.

## What a provider launch does

The same sequence as the probe, then `execve` of the shipping debug binary:

1. User namespace. The process is uid 0 inside it and the caller's uid outside it. While `CAP_SETPCAP` is still effective, `PR_CAPBSET_DROP` removes every valid capability from the bounding set. The permitted, effective, and inheritable sets are then cleared, and `no_new_privs` is set. The provider tests read `/proc/<host-pid>/status` of the process that is pid 1 in the new PID namespace. That file is the process's `/proc/self/status`. `CapBnd` is `0000000000000000`. Landlock does not grant `/proc`, so the host reads that node while the provider is answering.
2. Mount, network, IPC, and PID namespaces. The network namespace has only `lo`. The provider is pid 1 in its PID namespace.
3. One Landlock ruleset. Handled rights include every filesystem right through device ioctl on this kernel (ABI 6). `STORAGE_ROOT` gets mask `0x41be` and nothing else. The provider binary gets read and execute, because `execve` opens a binary for both.
4. One seccomp allow-list. A syscall that is not on the list returns `EPERM`. `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, and `recvmmsg` are refused by name before the allow-list is considered.

The probe keeps its own shorter allow-list. That list still has no `socket`, no `socketpair`, and no `clone`. `F-LC-SOCKET` still flips `DENY_SOCKET` in `src/policy.rs` and the probe test `did_profile_permits_its_operations_and_refuses_the_rest` fails because `socket` then succeeds.

`F-LC-CAPBND` comments out `drop_bounding_set()` and `confined_process_cap_bnd_is_zero` fails because `CapBnd` is not 0.

## The shipped launcher has no weaken switches

`--block-landlock`, `--block-seccomp`, `--block-userns`, and `--explain-abi` are compiled only when `setup.c` is built with `-DLC_TEST_HOOKS`. `build.rs` writes that binary as `lc-setup-test`. The fail-closed tests call that binary. The profile launches call `lc-setup`, which is built without the flag. On that binary each of those four arguments returns `linux confinement refused: unknown launch argument` and does not install a filter. `F-LC-BLOCK` adds `-DLC_TEST_HOOKS` to the `lc-setup` compile and `production_launcher_rejects_block_switches` fails because `--block-landlock` then reports that the kernel has no Landlock.

## Why STORAGE_ROOT is eight rights, not fifteen

The fail-closed guard's `FsRules::read_write_dir` grants `HANDLED_ACCESS_FS & !EXECUTE`, which is fifteen rights: every filesystem bit through device ioctl except execute (`0xfffe` when the handled mask is bits 0 through 15).

This launcher grants eight (`0x41be`):

| right | bit |
| --- | --- |
| `WRITE_FILE` | 1 |
| `READ_FILE` | 2 |
| `READ_DIR` | 3 |
| `REMOVE_DIR` | 4 |
| `REMOVE_FILE` | 5 |
| `MAKE_DIR` | 7 |
| `MAKE_REG` | 8 |
| `TRUNCATE` | 14 |

These seven stay denied on `STORAGE_ROOT`:

| right | bit | what granting it would allow in the storage root |
| --- | --- | --- |
| `MAKE_CHAR` | 6 | create a character device |
| `MAKE_SOCK` | 9 | create a UNIX socket node |
| `MAKE_FIFO` | 10 | create a named pipe |
| `MAKE_BLOCK` | 11 | create a block device |
| `MAKE_SYM` | 12 | create a symbolic link |
| `REFER` | 13 | link or rename a file to a different directory |
| `IOCTL_DEV` | 15 | ioctl a device node |

The ruleset still handles those seven, so an attempt is denied rather than ignored. A rename inside one directory does not need `REFER`. The three provider binaries complete their permitted operations with `0x41be`. The enforced line prints `storage_rights=0x41be`. `F-LC-STORAGE` adds `IOCTL_DEV` to the macro and `did_profile_permits_its_operations_and_refuses_the_rest` fails with `storage root rights drifted`. `withheld_storage_rights_are_landlock_eacces` lets `symlinkat`, `mknodat` and `linkat` through the probe filter and requires Landlock `EACCES` for make socket, fifo, symlink and device ioctl, and Landlock `EXDEV` for a withheld `REFER`. The same test requires an unconfined success for those rows. Device ioctl is `RNDGETENTCNT` on `/dev/urandom` (the launcher bind-mounts that node under `STORAGE_ROOT`); `ioctl(0)` on `/dev/null` is `ENOTTY` unconfined and is not a control. Opening a bind-mounted `/dev/ptmx` allocates a pty and the confined open is `EACCES`. `make-char` and `make-block` stay confined `EACCES` (Landlock-shaped) and are NOT PROVEN as positive controls: this uid has no `CAP_MKNOD` in the initial user namespace, and a user namespace also refuses char/block `mknod` (`EPERM`).

The guard's fifteen-right helper is a generic directory grant. This profile's storage root is a data directory, and the mask stays at the eight rights above. This lab does not edit the guard.

## Libraries

The binaries are glibc dynamic builds, which is how this repo builds them. The lab does not relink them static. `ldd` is the source of the extra paths. Each path is one Landlock rule.

| binary | path | rights | why |
| --- | --- | --- | --- |
| all three | `/lib64/ld-linux-x86-64.so.2` | read, execute | the kernel starts the binary through this dynamic linker |
| all three | `/lib/x86_64-linux-gnu/libc.so.6` | read, execute | `ldd` lists libc, and the linker maps it executable |
| all three | `/lib/x86_64-linux-gnu/libgcc_s.so.1` | read, execute | `ldd` lists libgcc_s, and the linker maps it executable |
| model-provider | `/lib/x86_64-linux-gnu/libm.so.6` | read, execute | `ldd` lists libm for this binary only |
| all three | `/etc/ld.so.cache` | read | the linker reads this cache before it opens those libraries |
| provider runs that record socket, exec, and signal | `lc-witness.so` built in this lab | read, execute | constructor inside the provider process; it is not a library the binary links |

`linux-vdso.so.1` is the kernel mapping. It is not a file rule. An open of `/proc/self/maps` returns `EACCES` under Landlock, and the three binaries still answer.

## Two deliberate widenings

**Unix socket pair (C9 departure).** `model-provider` starts a Tokio thread. That runtime calls `socketpair(AF_UNIX, ...)`. The provider filter allows `socketpair` only when the first argument is `AF_UNIX`. `socket` itself stays refused, including `AF_INET` and `AF_UNIX`. `socketpair(AF_INET)` is refused. Did and wallet do not call `socketpair`; the same filter covers them. The probe filter still refuses every pair. `F-LC-PROVIDER-SOCKET` flips `provider_deny_socket` and `provider_filter_refuses_socket` fails. See `CONFINEMENT-LINUX.md`.

`clone` is allowed only with `CLONE_THREAD`. `clone3` returns `ENOSYS`. `clone(SIGCHLD)` is refused under `mode=provider`. Every denied row asserts its exact errno. `F-LC-ANY-ERRNO` makes `expect()` ignore errno and returns `ENOSYS` for process clone; `provider_filter_refuses_clone_process` fails.

**Wallet parent.** Wallet init opens `STORAGE_PARENT` and syncs it. A Landlock rule on that directory would also cover every sibling. The launcher therefore bind-mounts `STORAGE_ROOT` aside, mounts a fresh tmpfs on `STORAGE_PARENT`, and bind-mounts the wallet directory back as the only child. The read rule is on that private parent. A host sibling is not in the mount. Did and model do not set this flag.

The model runtime creates a thread. The filter admits that as `clone` with `CLONE_THREAD`. The probe still refuses `clone`. Exec of any file other than the granted binary is Landlock's job: the copy under `STORAGE_ROOT` is readable and not executable.

## How each refusal was produced

The permitted rows are the provider's own stdin/stdout protocol, with no witness required for the answer. The witness is loaded on that same run so the three calls the protocol does not make are still inside the provider process:

- `socket(AF_INET, SOCK_STREAM, 0)` returns errno 1. Reason: `seccomp refused socket`.
- `kill` of the host supervisor pid returns errno 3. Reason: `the pid namespace has no such host process`.
- `execve` of the copy returns errno 13. Reason: `landlock refused exec of a file other than PROVIDER_EXECUTABLE`.

A second start asks `execve` to run that copy as the program and grants execute only on the original file. The launcher reports `linux confinement refused: exec of PROVIDER_EXECUTABLE failed errno=13` and the provider does not answer.

Outside read and write are the provider's own errors:

- did: `Permission denied (os error 13)` on the nickname read and the nickname write through a symlink to a file outside the root.
- wallet write: `failed to create wallet storage directory: Permission denied (os error 13)` for an `init` whose base is outside the root.
- wallet read: `failed to sync wallet storage directory: Permission denied (os error 13)` for an `init` whose wallet directory is a real directory outside the root.
- model write: `journal_access_denied: model run journal is not writable` for a journal directory outside the root.
- model read: `journal_corrupt: model run journal is unavailable` when `runs` is a symlink to a directory outside the root.

Hosted model dispatch stops in the binary with `Hosted external HTTPS is paused.` before it calls `socket`. The socket row above is the kernel refusal from that same process.

## What this does not prove

Jetson execution is NOT RUN. Real aarch64 execution is NOT RUN. `build.rs` honours `CC_aarch64_unknown_linux_gnu` / `TARGET_CC` / `aarch64-linux-gnu-gcc` and does not compile the C helpers with host `cc` when TARGET is aarch64. `cargo check --target aarch64-unknown-linux-gnu` is therefore not aarch64 proof when that compiler is absent. `tests/aarch64.rs` cross-compiles `setup.c` twice (production and `-DLC_TEST_HOOKS`), `probe.c`, and `witness.c` with `aarch64-linux-gnu-gcc`. Under `qemu-aarch64` the test binary's `--explain-abi` path runs, the production binary refuses `--block-landlock`, and the freestanding probe runs. It does not boot a Jetson and it does not run the provider binaries as aarch64, because those binaries were built for x86-64.

This lab is not the Runtime's provider bridge. A production launcher still has to own the library list, the wallet parent mount, and the Tokio socket-pair exception, and a reviewer should treat each of those as its own decision.
