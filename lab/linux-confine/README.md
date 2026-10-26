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
3. Every capability is removed from the bounding set, then the permitted,
   effective, and inheritable sets are cleared, then `no_new_privs` is set.
   The confined process status file shows `CapBnd` as 0.
4. One Landlock ruleset handles every filesystem right the ABI reports,
   including truncate and device ioctl. `STORAGE_ROOT` gets eight rights,
   mask `0x41be`: read file, read directory, write file, truncate, make a
   regular file, make a directory, remove a file, and remove a directory.
   Character devices, sockets, fifos, block devices, symlinks, refer, and
   device ioctl stay denied on that directory. `PROVIDER_EXECUTABLE` gets
   read and execute. A provider launch also gets the library paths named
   below.
5. One seccomp allow-list returns `EPERM` for every number that is not listed.
   The probe list has no `socket` and no `socketpair`. The provider list is
   the larger set the binaries use, and it still refuses `socket` and every
   connect, bind, listen, and accept.

Linux `execve` opens a binary for read and execute, so the executable rule
carries both rights. A copy under `STORAGE_ROOT` is readable and is not
executable.

Landlock cannot name `STORAGE_PARENT` without the tree under it, and a rule on
`/` would grant the whole tree. Those two macOS allows become no rule. A read
of either path is refused. `sysctl-read` becomes one fact call, `uname`.

The freestanding probe checks the short filter. The provider tests exec the
debug binaries from:

```bash
cargo build --manifest-path capsules/did-provider/Cargo.toml --bin did-provider
cargo build --manifest-path capsules/wallet-provider/Cargo.toml --bin wallet-provider
cargo build --manifest-path capsules/model-provider/Cargo.toml --bin model-provider
```

Those are the binaries the macOS confinement tests launch. Each provider
launch adds the paths `ldd` prints: read and execute for the dynamic linker
and each shared library, and read-only for `/etc/ld.so.cache`. The test
prints the reason for each path. The repo builds these binaries against
glibc, so this lab does not relink them static.

Wallet init syncs `STORAGE_PARENT`. Landlock cannot grant that directory
without its tree, so the launcher mounts a private parent that contains only
`STORAGE_ROOT` and then grants read of that parent.

`model-provider` starts a Tokio thread that creates one `AF_UNIX`
`socketpair`. The provider filter allows that pair and refuses `socket`.
Did and wallet do not call `socketpair`. The probe filter still refuses both.

A witness constructor is loaded with `LD_PRELOAD` into the provider process.
It calls `socket`, `kill` of the host supervisor, and `execve` of a copy,
records the errno, and returns. The provider's own main then answers the
protocol. The copy is also started once as the program, with execute granted
only on the original file.

`default_account`, `list_approvals`, `runs_events`, and `runs_cancel` have
no named macOS test, so this lab does not claim them.

If Landlock or seccomp is unavailable, or the Landlock ABI is below 5, the
launcher writes a refusal and does not exec the probe. The same is true when
user namespaces are turned off. The switches that simulate those absences,
and `--explain-abi`, are compiled only into `lc-setup-test`. The launcher
the tests exec for a real profile, `lc-setup`, answers each of those
arguments with `unknown launch argument`.

Syscall numbers come from the platform headers (`<sys/syscall.h>` in the
launcher and the probe). The audit architecture is chosen with the compiler
target. The source is the same on x86-64 and aarch64.

```bash
cargo test --manifest-path lab/linux-confine/Cargo.toml -- --test-threads=1 --nocapture
python3 lab/linux-confine/falsify.py
```

`build.rs` honours the cargo target the same way the `cc` crate does: `CC_aarch64_unknown_linux_gnu`, then `TARGET_CC`, then `aarch64-linux-gnu-gcc`. Host `cc` is used only when TARGET equals HOST. `cargo check --target aarch64-unknown-linux-gnu` is not aarch64 proof: without that target compiler the C helpers do not build, and real aarch64 execution is NOT RUN.

`tests/aarch64.rs` `aarch64_launcher_compiles` is `#[ignore]`. It cross-compiles the launcher, the test launcher, the probe, and the witness with `aarch64-linux-gnu-gcc` and runs the explain path on the test launcher and the probe under `qemu-aarch64`. When those tools are absent the test is ignored, never counted as a pass, and panics if someone runs it with `--ignored`. The production aarch64 launcher refuses `--block-landlock`. Jetson execution is NOT RUN.

The second command plants six bugs, one at a time, and restores each file. It prints `F-LC-SOCKET CAUGHT`, `F-LC-CAPBND CAUGHT`, `F-LC-BLOCK CAUGHT`, `F-LC-STORAGE CAUGHT`, `F-LC-PROVIDER-SOCKET CAUGHT`, and `F-LC-ANY-ERRNO CAUGHT`.

`socketpair(AF_UNIX)` on the provider filter is a named C9 departure. See `CONFINEMENT-LINUX.md`. `clone(SIGCHLD)` is refused. Every denied row asserts its exact errno. The withheld Landlock rights that have a same-test unconfined success are proven by that pair. `make-char` and `make-block` stay NOT PROVEN for the positive control: this uid has no `CAP_MKNOD` in the initial user namespace, and a user namespace also refuses char/block `mknod`.
