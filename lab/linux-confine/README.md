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

`build.rs` honours the cargo target the same way the `cc` crate does: `CC_aarch64_unknown_linux_gnu`, then `TARGET_CC`, then `aarch64-linux-gnu-gcc`. Host `cc` is used only when TARGET equals HOST. After each foreign-target compile it reads ELF `e_machine` of the helper (and of each archive member) and panics unless that is `EM_AARCH64` (183) for aarch64 or `EM_X86_64` (62) for x86_64. `TARGET_CC=cc` therefore fails an aarch64 check instead of writing x86-64 objects under the aarch64 out dir.

`cargo check --target aarch64-unknown-linux-gnu` with the real `aarch64-linux-gnu-gcc` now compiles and the helpers are `EM_AARCH64=183`. That is an aarch64 **build**. It is not native aarch64 execution and it is not Jetson.

`tests/aarch64.rs` has one always-on label test and one ignored qemu-user test:

- `qemu_user_mode_label_is_not_native_or_jetson` — the mode string is `aarch64 build + qemu-user (host kernel)`.
- `aarch64_qemu_user_host_kernel` is `#[ignore]`. It cross-compiles the launcher, the test launcher, the probe, the witness, and `helper/landlock-probe.c`, checks each ELF `e_machine` is 183, then runs them under `qemu-aarch64`. qemu-user 8.2.2 does **not** implement `landlock_*` (`Unknown syscall 444/445/446`, guest `ENOSYS` / errno 38). The launcher therefore fail-closes with `the kernel has no Landlock`. `--explain-abi` is only a compiled table and does not call Landlock. When the tools are absent the test is ignored, never counted as a pass, and panics if someone runs it with `--ignored`. Never native aarch64. Never Jetson.

Running the aarch64-built `confine` / `providers` **test binaries** under qemu-user is the same mode. qemu-user does not wrap child `execve` of those aarch64 helpers as a host `qemu-aarch64` (binfmt was not registered here), and Landlock is `ENOSYS`, so those suites do not prove C9 rows. Label: `aarch64 build + qemu-user (host kernel)`.

`qemu-system-aarch64` TCG with Alpine `vmlinuz-virt` (`Linux 6.18.58-0-virt`) is a real aarch64 guest kernel, not qemu-user. A static `landlock_create_ruleset` under that kernel reports **ABI 7** (`IOCTL_DEV` needs ABI >= 5). Label every such run `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`. Never native. Never Jetson.

```bash
lab/linux-confine/run-aarch64-guest.sh          # full C9 + in-guest plants
lab/linux-confine/run-aarch64-guest.sh smoke    # ABI probe only
```

The script cross-builds the confine, elf, aarch64 and providers test binaries plus the three shipping provider binaries for `aarch64-unknown-linux-gnu`, packs them into an Alpine 3.23 minirootfs initramfs with the glibc loader, and boots `qemu-system-aarch64 -accel tcg`. Evidence lands in `lab/linux-confine/evidence/aarch64-qemu-system-6.18/`.

Inside that guest (uid 1000): elf 6/6, aarch64 2/2 with the qemu-user row ignored, confine 25/25 (`enforced abi=7`, `ioctl-dev` EACCES), providers 4/4, and the nine in-guest plants CAUGHT (the original six plus skip-netns, drop-seccomp, and widen-Landlock). The guest has a NIC besides `lo` so skip-netns reports `netns=host`. The host script exits non-zero if a suite fails, is missing, reports the wrong counts, is missing an `LC_MARK` serial line, a suite has two `LC_MARK` lines, an unexpected or unparseable `LC_MARK` appears (ASCII single-space grammar only), an extra fail file appears, `guest_exit.txt` is not exactly one canonical LF-terminated line, the nonce does not match the host pre-boot hash bound to this `$WORK` and run id, a nonce was already recorded on this host boot, a PREBOOT path is a symlink, a hardlink, or contains `..`, `run_start` is 0 or in the future, an evidence file predates that run or has a future mtime, qemu exits non-zero, or qemu hits the hard timeout. Used nonces live in a host-side ledger outside `$WORK` and 9p. The host writes the nonce hash, run id, and `$WORK` path outside the 9p share before qemu starts. The guest nonce is a root-only file that init reads after the test uid finishes; it is not in `/etc/lc-guest.env` or `evidence/` during the run. That guest is still not Jetson and not a real ARM board.

The second command plants confinement bugs, one at a time, and restores each file. It also sets `TARGET_CC=cc` for the aarch64 check (after dropping leftover `CC_*` so a real cross `CC_<target>` cannot hide the plant) and plants a skip of the ELF `e_machine` test. It plants an errno-0 expectation on the qemu-user Landlock probe. It prints `F-LC-SOCKET CAUGHT`, `F-LC-CAPBND CAUGHT`, `F-LC-BLOCK CAUGHT`, `F-LC-STORAGE CAUGHT`, `F-LC-PROVIDER-SOCKET CAUGHT`, `F-LC-ANY-ERRNO CAUGHT`, `F-LC-SKIP-NETNS CAUGHT`, `F-LC-DROP-SECCOMP CAUGHT`, `F-LC-WIDE-ROOT CAUGHT`, `F-LC-WRONG-ARCH-CC CAUGHT`, and `F-LC-QEMU-USER-LANDLOCK CAUGHT`.

`socketpair(AF_UNIX)` on the provider filter is a named C9 departure. See `CONFINEMENT-LINUX.md`. `clone(SIGCHLD)` is refused. Every denied row asserts its exact errno. The withheld Landlock rights that have a same-test unconfined success are proven by that pair. Device ioctl is `RNDGETENTCNT` on `/dev/urandom`. `make-char` and `make-block` stay NOT PROVEN for the positive control: this uid has no `CAP_MKNOD` in the initial user namespace, and a user namespace also refuses char/block `mknod`.

The ignored qemu-user test is:

```bash
cargo test --manifest-path lab/linux-confine/Cargo.toml --test aarch64 \
  -- --ignored --exact aarch64_qemu_user_host_kernel --nocapture
```
