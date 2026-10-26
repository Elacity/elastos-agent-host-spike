# Review notes for @irzhyran

This is lab code under `lab/linux-confine/`. It does not change the Runtime launcher, the provider sources, or the macOS profiles. The profiles in `capsules/*/confine.sb` and their `declared-rights.json` files stay the oracle. The lab reads them.

## What a provider launch does

The same sequence as the probe, then `execve` of the shipping debug binary:

1. User namespace. The process is uid 0 inside it and the caller's uid outside it. Every capability is then dropped, and `no_new_privs` is set.
2. Mount, network, IPC, and PID namespaces. The network namespace has only `lo`. The provider is pid 1 in its PID namespace.
3. One Landlock ruleset. Handled rights include every filesystem right through device ioctl on this kernel (ABI 6). `STORAGE_ROOT` gets read and write, including create, remove, and truncate. The provider binary gets read and execute, because `execve` opens a binary for both.
4. One seccomp allow-list. A syscall that is not on the list returns `EPERM`. `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, and `recvmmsg` are refused by name before the allow-list is considered.

The probe keeps its own shorter allow-list. That list still has no `socket`, no `socketpair`, and no `clone`. `F-LC-SOCKET` still flips `DENY_SOCKET` in `src/policy.rs` and the probe test `did_profile_permits_its_operations_and_refuses_the_rest` fails because `socket` then succeeds.

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

**Unix socket pair.** `model-provider` starts a Tokio thread. That runtime calls `socketpair(AF_UNIX, ...)`. The provider filter allows `socketpair` only when the first argument is `AF_UNIX`. `socket` itself stays refused, including `AF_INET`. Did and wallet do not call `socketpair`; the same filter covers them. The probe does not get this exception.

**Wallet parent.** Wallet init opens `STORAGE_PARENT` and syncs it. A Landlock rule on that directory would also cover every sibling. The launcher therefore bind-mounts `STORAGE_ROOT` aside, mounts a fresh tmpfs on `STORAGE_PARENT`, and bind-mounts the wallet directory back as the only child. The read rule is on that private parent. A host sibling is not in the mount. Did and model do not set this flag.

`clone` and `clone3` are on the provider allow-list because the model runtime creates a thread (`clone3` with `CLONE_THREAD`). The probe still refuses `clone`. Exec of any file other than the granted binary is Landlock's job: the copy under `STORAGE_ROOT` is readable and not executable.

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

Jetson execution is NOT RUN. `tests/aarch64.rs` cross-compiles `setup.c`, `probe.c`, and `witness.c` with `aarch64-linux-gnu-gcc` and runs the aarch64 setup's `--explain-abi` path and the freestanding probe under `qemu-aarch64`. It does not boot a Jetson and it does not run the provider binaries as aarch64, because those binaries were built for x86-64.

This lab is not the Runtime's provider bridge. A production launcher still has to own the library list, the wallet parent mount, and the Tokio socket-pair exception, and a reviewer should treat each of those as its own decision.
