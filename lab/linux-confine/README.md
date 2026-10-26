# Linux confinement

This lab enforces the three provider profiles on Linux. The profiles stay
where the macOS lane wrote them:

- `capsules/did-provider/confine.sb`
- `capsules/wallet-provider/confine.sb`
- `capsules/model-provider/confine.sb`

Each profile is read, not copied. Its declared rights are the allows in the
matching `declared-rights.json`. One launcher applies every profile:

1. A user namespace maps the process to uid 0 inside the namespace and to the
   caller's uid outside it.
2. Mount, network, IPC, and PID namespaces are created. The network namespace
   has only `lo`.
3. Every capability is dropped, then `no_new_privs` is set.
4. One Landlock ruleset handles every filesystem right the ABI reports,
   including truncate and device ioctl. The only path rules are read and write
   on `STORAGE_ROOT`, and read plus execute on `PROVIDER_EXECUTABLE`.
5. One seccomp allow-list permits the probe's syscalls and returns `EPERM` for
   every other number. `socket` and `socketpair` are not on the list.

Linux `execve` opens a binary for read and execute, so the executable rule
carries both rights. A copy under `STORAGE_ROOT` is readable and is not
executable.

Landlock cannot name `STORAGE_PARENT` without the tree under it, and a rule on
`/` would grant the whole tree. Those two macOS allows become no rule. A read
of either path is refused. `sysctl-read` becomes one fact call, `uname`.

The probe is freestanding. The shipping provider binaries are dynamically
linked, and these profiles grant no library path, so this lab does not exec
them. A storage operation is proved by writing and reading the file that
operation's row names. An in-memory operation is proved by the confined
process running without a file or a socket. `default_account`,
`list_approvals`, `runs_events`, and `runs_cancel` have no named macOS test,
so this lab does not claim them.

If Landlock or seccomp is unavailable, or the Landlock ABI is below 5, the
launcher writes a refusal and does not exec the probe. The same is true when
user namespaces are turned off.

Syscall numbers come from the platform headers (`<sys/syscall.h>` in the
launcher and the probe). The audit architecture is chosen with the compiler
target. The source is the same on x86-64 and aarch64.

```bash
cargo test --manifest-path lab/linux-confine/Cargo.toml -- --nocapture
python3 lab/linux-confine/falsify.py
```

The second command removes the socket denial, shows
`did_profile_permits_its_operations_and_refuses_the_rest` fail, restores the
denial, and prints `F-LC-SOCKET CAUGHT`.
