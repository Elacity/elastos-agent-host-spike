# fail-closed-linux: a provider launch guard that fails closed (M1 C0 lab)

This lab proves one rule on Linux: a provider starts confined, or it does not
start. The guard runs in the provider's own process, after `fork` and before
`exec`. If any confinement step fails, `exec` does not run, and the guard
returns a refusal that names the provider, the layer, the step and the OS
error. The launcher CLI exits 71. There is no fallback path.

This is a lab model, not Runtime code. Runtime integration is separate work.

## The guard

`confine` in `src/lib.rs` applies six layers in this order. The first failed
step stops it.

| Layer | Steps | What the step does |
| --- | --- | --- |
| user-namespace | `unshare`, `uid_map`, `setgroups`, `gid_map` | `unshare(CLONE_NEWUSER)`, then maps the caller's own uid and gid to themselves |
| pid-namespace | `unshare_pid` | `unshare(CLONE_NEWPID)`. The caller stays in the old PID namespace. A later fork puts the provider in the new one. A failed unshare refuses: `the PID namespace cannot be created` |
| capabilities | `cap_last_cap`, `bounding_set`, `ambient_set`, `capset` | `PR_CAPBSET_DROP` for every capability up to `/proc/sys/kernel/cap_last_cap`, `PR_CAP_AMBIENT_CLEAR_ALL`, then `capset` to all zero |
| no_new_privs | `set_no_new_privs` | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| seccomp | `install_filter` | `seccomp(SECCOMP_SET_MODE_FILTER)` with the filter in `src/seccomp.rs` |
| landlock | `abi_probe`, `abi_floor`, `right_probe`, `create_ruleset`, `storage_root_rule`, `executable_rule`, `restrict_self`, `enforce_self` | probes the kernel ABI, then requires every right the shared file profile needs (`truncate` at ABI 3, `ioctl_dev` at ABI 5). A missing right refuses and names the right and the ABI that first expresses it. Then it try-creates a ruleset for each needed right; `EINVAL` is a named `right_probe` refusal so a lying ABI number cannot hide a missing bit. After `restrict_self` a throwaway child tries one denied op per needed right (write outside the root, truncate, ioctl on a fresh pty). Any success is a refusal: the kernel accepted a right and did not enforce it. The ruleset handles only bits that ABI knows. The storage grant is the eight-right mask (no `REFER`, no `ioctl_dev`, no special-file create). ABI 6 also sets `LANDLOCK_SCOPE_SIGNAL`. |
| launch | `close_fds` | before exec, close every fd except stdin, stdout, stderr and the fault pipe (`close_range`, or `/proc/self/fd` if that syscall is missing). A pre-confine pty cannot be inherited. |

After the six layers, `execve` starts the provider with an empty environment.
`unshare(CLONE_NEWPID)` does not move the caller. `detach_into_pid_namespace`
forks a PID-1 init, writes that host pid to the parent, and the helper
exits. Init forks the provider (PID 2), sets `PR_SET_PDEATHSIG` on the
provider, and reaps every child with `waitpid(-1)`. `launch` returns init.
SIGKILL of that pid kills PID 1 and the namespace. SIGTERM on init kills
every other process in the namespace and then exits. No host-namespace
helper stays beside the provider.

The bounding set is dropped before `capset`, because `PR_CAPBSET_DROP` needs
`CAP_SETPCAP` and `capset` removes it. On this host the opposite order left
`CapBnd` at `000001ffffffffff`.

There is no single ABI floor. The guard computes the rights the profile
needs, probes the running ABI, and refuses when a needed right is missing.
`ProviderSpec::require_landlock_abi` and `fcl-launch --require-landlock-abi N`
can raise an extra ABI number on top of that check. They cannot skip a
needed right.

The seccomp filter kills a process that uses a foreign architecture. On
x86-64 it returns EPERM for every x32 call. It returns EPERM for sockets,
`ptrace`, namespace calls, `mount`, `bpf`, module loading and the other calls
in `DENIED`, and for `clone` with a namespace flag. It returns ENOSYS for
`clone3`. It allows all other calls. This filter is a deny-list. A
per-provider allow-list is profile work (see the PR #296 section below).

## Refusal and exit codes

```text
fail-closed-linux refused to start did-provider: layer landlock, step abi_floor: this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5); the provider was not started
fail-closed-linux refused to start wallet-provider: layer capabilities, step capset: Operation not permitted (os error 1); the provider was not started
```

`fcl-launch` exits 71 on a refusal and 64 on a usage error. Otherwise it waits
for the provider and returns the provider's exit code, or 128 plus the signal
number.

The real kernel (`src/real.rs`) creates a close-on-exec pipe and forks. The
child runs the guard. On a fault, the child writes a 12-byte record (step,
errno, found ABI) and calls `_exit(71)`. EOF on that pipe is necessary for
a start, not sufficient. The parent samples `/proc/<provider pid>/exe`
against the expected binary (device and inode from `stat` before fork)
on a side thread while the provider is still alive. A match is a start. Closing the pipe
without `execve` leaves the helper image in place and is a refusal. A
static binary that writes nothing is accepted when that identity matches.
Any bytes, including a `ConfineReady` record without `execve`, are a
refusal.
If the helper dies before `execve` and there is no live init, that empty
read is also a refusal. The child uses only data that `Plan` built before
the fork, and it makes only system calls: it does not allocate, lock or
panic.

`launch` returns the refusal and starts nothing. No API in this crate starts
an unconfined provider.

## The `Kernel` trait

`Kernel` has one method per step, plus `exec` and `spawn_confined`.
`RealKernel` makes the Linux system calls. `SimKernel` (`src/sim.rs`) fails one
chosen step with a chosen errno. It records each step and each exec, and it
runs the guard in the calling process.

## Run

From the repository root:

```bash
lab/fail-closed-linux/run.sh
```

`run.sh` runs `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked`, and then `python3 falsify.py`. It sets `CARGO_TARGET_DIR`
and `CARGO_BUILD_BUILD_DIR` under this folder, because the repository's
`.cargo/config.toml` otherwise shares one build dir across workspaces.

`build.rs` builds `probe/main.rs` with `-C target-feature=+crt-static`. The
probe is static, so the Landlock domain needs no library path. The build needs
static glibc (`libc.a`, from `libc6-dev` on Ubuntu). For a target other than
the host, `build.rs` skips the probe, so `cargo check --target ...` still works.

The real-kernel tests need unprivileged user namespaces, a PID namespace,
seccomp, and a Landlock ABI that can express `truncate` and `ioctl_dev`
(ABI 5 or above).

## Results on this host

Linux x86_64, kernel 6.12.94+, rustc 1.91.0, Landlock ABI 6.

| Suite | Tests |
| --- | --- |
| `lib` (unit) | 9 passed |
| `simulated` | 19 passed |
| `real_kernel` | 26 passed |

Each refusal row runs for `did-provider`, `wallet-provider` and
`model-provider` in both suites. A real-kernel row uses the real `fcl-launch`
binary and the guard's real system calls on this kernel. On some rows a
kernel rule makes the step fail. On the other rows the launcher inherits a
seccomp filter that makes one system call fail. In that case the kernel's
seccomp gives the errno, and the feature itself is present.

| Row | Simulated kernel | Real kernel | How the real step fails |
| --- | --- | --- | --- |
| user namespaces off | `sim_user_namespaces_off_refuses` (EPERM, ENOSPC) | `real_user_namespaces_off_refuses` | kernel rule: a parent user namespace with `max_user_namespaces` 0 gives ENOSPC; inherited filter: `unshare` gives EPERM |
| PID namespace cannot be created | `sim_pid_namespace_unavailable_refuses` (EPERM, ENOSYS, ENOSPC) | `real_pid_namespace_unavailable_refuses` | inherited filter: `unshare(CLONE_NEWPID)` gives EPERM |
| id maps cannot be written | `sim_id_maps_unwritable_refuses` (`uid_map`, `setgroups`, `gid_map`) | `real_id_map_unwritable_refuses` | kernel rule: a launcher binary with mode 0111 makes the process not dumpable, so opening `/proc/self/uid_map` gives EACCES |
| capability drop fails | `sim_capability_drop_failure_refuses` (all four steps) | `real_capability_drop_failure_refuses` | inherited filter: `capset` gives EPERM; `prctl(PR_CAPBSET_DROP)` gives EPERM |
| no_new_privs cannot be set | `sim_no_new_privs_failure_refuses` | `real_no_new_privs_failure_refuses` | inherited filter: `prctl(PR_SET_NO_NEW_PRIVS)` gives EPERM |
| seccomp cannot be installed | `sim_seccomp_install_failure_refuses` (EINVAL, ENOSYS) | `real_seccomp_install_failure_refuses` | inherited filter: `seccomp` gives ENOSYS |
| Landlock missing | `sim_landlock_missing_refuses` (ENOSYS, EOPNOTSUPP) | `real_landlock_missing_refuses` | inherited filter: `landlock_create_ruleset` gives ENOSYS or EOPNOTSUPP |
| Landlock ABI too old | `sim_landlock_abi_too_old_refuses` (ABI 1 to 4 name the missing right; ABI 6 with 7 required) | `real_landlock_abi_below_required_refuses` | kernel rule: `--require-landlock-abi` set to the host ABI plus 1 |
| Per-right floor on this ABI 6 host | `sim_test_extra_right_refuses_on_abi_6` | `real_per_right_floor_refuses_on_this_kernel` | test hook: `--test-require-right future_fs` (needs ABI 7) with `FCL_TEST_HOOKS=1`. The extra floor is not this row |
| Extra floor still names the right | `sim_extra_floor_still_names_the_missing_right` | `real_extra_floor_still_names_the_missing_right` | both `--require-landlock-abi host+1` and the test extra right; the refusal names `future_fs` |
| Empty fault pipe (early death) | `execve_eof_is_a_start_and_confine_ready_is_a_refusal` | `real_empty_fault_pipe_is_not_a_start` | test hook: `--test-empty-pipe` with `FCL_TEST_HOOKS=1`. The helper exits before init or exec; spawn refuses |
| ConfineReady without exec | same lib row | `real_confine_ready_without_exec_is_not_a_start` | test hook: `--test-confine-ready`. Any bytes, including a ready record, are a fault |
| Close pipe without execve | `exe_identity_requires_matching_dev_and_inode` | `real_close_pipe_without_exec_is_not_a_start` | test hook: `--test-close-pipe`. EOF plus a live init is not a start unless `/proc/<pid>/exe` matches |
| Inherited pty ioctl | — | `real_inherited_pty_ioctl_is_not_available` | launcher inherits a pre-confine pty on fd 3; confined `TIOCGWINSZ` is `EBADF` |
| Lying enforcement | `sim_lying_kernel_enforcement_refuses` | `real_lying_enforcement_self_test_refuses` | SimKernel reports a denied op succeeded. Real hook: `--test-lie-enforcement` |
| Silent expected binary | — | `real_silent_expected_binary_is_a_start` | static binary writes nothing; start is accepted because exe identity matches |
| Lying ABI rights | `sim_lying_abi_5_with_abi_1_rights_refuses` | `real_lying_rights_probe_refuses` | SimKernel reports ABI 5 but accepts only ABI 1 bits. Real hook: `--test-lie-rights` |
| Landlock ruleset cannot be applied | `sim_landlock_ruleset_unappliable_refuses` (all four steps) | `real_landlock_ruleset_unappliable_refuses` | kernel rule: 16 inherited Landlock domains make `restrict_self` give E2BIG; inherited filter: `restrict_self` gives EPERM |

The positive tests:

- `sim_confined_provider_starts_after_every_layer` checks the order of the
  six layers, one bounding drop per capability, and one exec.
- `real_confined_provider_has_every_layer` starts the probe and reads the
  returned pid (PID-namespace init) from outside. It sees `NoNewPrivs: 1`,
  `Seccomp: 2`, `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` all zero,
  an identity `uid_map`, a user namespace that differs from the test's, a
  PID namespace that differs from the test's, `NSpid` ending in 1, and no
  extra child of the launcher beside init. Inside, the probe sees EPERM on
  an inet socket and a unix socket, EACCES on a read and a write outside
  its storage root and on `/etc/passwd`, a working write, read and
  `truncate` inside its storage root, `truncate` and `O_TRUNC` of the
  outside file denied, and `TIOCGWINSZ` on a pty slave opened after
  confine denied with Landlock `EACCES` (13). The same `TIOCGWINSZ` on
  that pty succeeds unconfined. It prints `nspid=2`.
- `real_confined_child_cannot_signal_host` asks the probe to `kill` the test
  process's real pid (`kill(pid, 0)`). The kernel returns ESRCH or EPERM; the
  test records that errno. The same probe forks a child in its namespace and
  `kill`s that child successfully.
- `real_pid_namespace_unavailable_refuses` inherits a seccomp filter that
  makes `unshare(CLONE_NEWPID)` return EPERM. The refusal names
  `the PID namespace cannot be created`.
- `real_reaper_propagates_exit_status` starts the probe with `--exit 42` and
  requires the launcher to exit 42.
- `real_reaper_forwards_signal` sends SIGTERM to the returned init pid.
  Init takes the namespace down. The launcher exits 128+SIGTERM. The
  probe is gone afterwards.
- `real_sigkill_returned_pid_tears_down_namespace` sends SIGKILL to init.
  Init, the provider and the namespace are gone.
- `real_daemonize_keeps_namespace_until_init_dies` has the probe fork and
  exit. The grandchild stays. SIGKILL of init then takes it down.
- `real_init_reaps_orphaned_grandchild` double-forks an exiting grandchild.
  Init reaps it. No zombie remains while the provider is still running.

Two more checks: `sim_every_guard_step_failure_stops_before_exec` fails each
guard step in turn, and `sim_landlock_abi_floor_cannot_be_lowered` shows that
`--require-landlock-abi 3` on ABI 4 still refuses because `ioctl_dev` needs
ABI 5.

`sim_per_right_floor_for_each_abi` walks ABI 1 through 6 for each provider.
`sim_missing_right_is_never_silently_dropped` requires the named-right
refusal on ABI 1-4. `sim_add_path_rule_rejects_access_outside_handled_fs`
makes `SimKernel` return `EINVAL` when a path rule asks for a bit the
ruleset does not handle, matching the kernel.

`--test-require-right`, `--test-empty-pipe`, `--test-confine-ready`,
`--test-lie-rights`, `--test-close-pipe` and `--test-lie-enforcement` are
linux-confine-style test switches. They are accepted only when
`FCL_TEST_HOOKS=1`. Without that env the production CLI reports
`unknown argument` and exits 64. The extra right can only add a refusal.
It cannot drop truncate or `ioctl_dev`. `--readable-path` grants read on
one extra path so the probe can open the pty after confine.
`--test-close-pipe` closes the fault write end without `execve`.
`--test-lie-enforcement` makes the self-test report that a denied op
succeeded.

## Per-right table (did, wallet, model)

The three providers share one file-profile contract: `(deny default)`,
`(deny network*)`, exec of `PROVIDER_EXECUTABLE`, and read/write under
`STORAGE_ROOT`. The needed Landlock rights whose absence is a wider sandbox
are `truncate` (ABI 3) and `ioctl_dev` (ABI 5). `REFER` (ABI 2) is not
needed: the kernel already denies reparent when that bit is absent. TCP
bind/connect (ABI 4) is not needed for the launch decision: seccomp already
denies `socket`.

| Reported ABI | Kernel that first shipped it | Launch? | Refusal names | Ruleset if it launched |
| --- | --- | --- | --- | --- |
| absent | — | refuse | Landlock is not available | none |
| 1 | 5.13 | refuse | `truncate` (needs ABI 3); `ioctl_dev` (needs ABI 5) | none |
| 2 | 5.19 | refuse | `truncate` (needs ABI 3); `ioctl_dev` (needs ABI 5) | none |
| 3 | 6.2 | refuse | `ioctl_dev` (needs ABI 5) | none |
| 4 | 6.7 | refuse | `ioctl_dev` (needs ABI 5) | none |
| 5 | 6.10 | launch | — | all ABI 5 filesystem bits handled; eight-right storage grant; TCP handled and not granted; `LANDLOCK_SCOPE_SIGNAL` unset (named gap) |
| 6 | 6.12 | launch | — | same as ABI 5, plus `LANDLOCK_SCOPE_SIGNAL` |

A 5.15-class kernel (JetPack R36.4.7 / L4T 36.4, typically `5.15.148-tegra`)
reports Landlock ABI 1 when the LSM is on, or `ENOSYS`/`EOPNOTSUPP` when it
is off. In both cases the three providers refuse. There is no per-right
floor that both starts them on 5.15 and denies truncate. This lab did not
boot a Jetson; that ABI is not a measurement from the board.

## PID namespace and `LANDLOCK_SCOPE_SIGNAL`

The design's carrier for `(deny default)` signals is a PID namespace
(`capsules/wallet-provider/CONFINEMENT-LINUX.md`). This lab unshares
`CLONE_NEWUSER`, writes the maps, then unshares `CLONE_NEWPID`. A failed
PID unshare is a refusal: `the PID namespace cannot be created`. After the
other layers, the helper forks a PID-1 init, writes that host pid, and
exits. Init forks the provider and reaps every child (`waitpid(-1)`).
`launch` returns init. The fault pipe stays close-on-exec on the
provider; helper and init close their copies so a successful `execve`
is EOF.

`LANDLOCK_SCOPE_SIGNAL` exists from ABI 6. The guard sets it when the probe
returns 6 or above, and fails closed if `create_ruleset` then fails. ABI 5
can launch and still cannot set the bit: that is a named gap, not a
refusal. `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` stays unset; seccomp already
denies `socket`.

## Falsifiers

`falsify.py` reads each plant in `mutants/`. For each plant, it copies this
crate to `target/falsify/<id>/crate`, applies the plant there, and runs the
named tests with that copy's own `CARGO_TARGET_DIR` and build dir. A plant is
caught when every named test fails. The control plant changes only a comment.
It must survive: the whole suite passes on its copy. Logs go to
`target/falsify/<id>.log`, and each copy is deleted after its run.

| Plant | What it breaks | Caught by |
| --- | --- | --- |
| F01-fallback-restarts-unconfined | `launch` restarts the provider with `std::process::Command` after a refusal | 3 simulated, 2 real-kernel tests |
| F02-cli-fallback-runs-unconfined | `fcl-launch` runs the command itself after a refusal | 3 real-kernel tests |
| F03-child-execs-after-refusal | the child calls `exec` even when `confine` failed | 2 simulated, 2 real-kernel tests |
| F04-userns-error-ignored | an `unshare` error is ignored | the user-namespace row in both suites |
| F05-uid-map-error-ignored | a `uid_map` error is ignored | the id-map row in both suites |
| F06-capset-error-ignored | a `capset` error is ignored | the capability row in both suites |
| F07-bounding-set-not-dropped | no `PR_CAPBSET_DROP` | both positive tests |
| F08-no-new-privs-error-ignored | a `no_new_privs` error is ignored | the no_new_privs row in both suites |
| F09-seccomp-error-ignored | a seccomp install error is ignored | the seccomp row in both suites |
| F10-landlock-missing-tolerated | a missing Landlock skips the layer | the Landlock-missing row in both suites |
| F11-abi-floor-off-by-one | ABI 6 passes an extra required ABI of 7 | the extra-floor ABI rows in both suites |
| F18-missing-right-silently-passed | a missing needed right is ignored and the start continues | the per-right ABI rows |
| F19-pid-unshare-skipped | `unshare(CLONE_NEWPID)` is skipped | `real_confined_provider_has_every_layer`, `real_confined_child_cannot_signal_host` |
| F23-sim-ignores-access-mask | SimKernel accepts a path rule outside `handled_fs` | `sim_add_path_rule_rejects_access_outside_handled_fs` |
| F24-extra-floor-hides-missing-right | `--require-landlock-abi` is checked before a missing right | the extra-floor-names-right rows |
| F25-empty-pipe-reported-as-start | `ConfineReady` without `execve` is treated as a start | the ConfineReady rows |
| F26-test-extra-right-ignored | the test-only extra right is dropped from the mask | the per-right extra-right rows |
| F27-helper-survives-as-returned-pid | helper stays in the host PID ns and is the returned pid | SIGKILL + confined-layers rows |
| F28-first-child-exit-tears-down | init exits when the first child exits | the daemonize row |
| F29-init-does-not-reap-all | init never `waitpid(-1)` | the orphan-grandchild row |
| F31-lying-abi-probe-skipped | the rights probe is skipped | the lying-ABI rows |
| F32-ioctl-dev-dropped-from-handled | `IOCTL_DEV` is dropped from `handled_fs` | `real_confined_provider_has_every_layer` |
| F33-inherited-fds-left-open | inherited fds are not closed before exec | `real_inherited_pty_ioctl_is_not_available` |
| F34-enforcement-self-test-skipped | the post-restrict self-test is skipped | lying-enforcement rows in both suites |
| F35-close-pipe-reported-as-start | closing the fault pipe without `execve` is a start | `real_close_pipe_without_exec_is_not_a_start` |
| F12-restrict-self-error-ignored | a `restrict_self` error is ignored | the ruleset row in both suites |
| F13-socket-allowed | `socket` removed from the seccomp deny-list | `real_confined_provider_has_every_layer` |
| F14-storage-rule-covers-parent | the Landlock storage rule names the parent directory | `real_confined_provider_has_every_layer` |
| F15-refusal-omits-provider | the refusal text drops the provider name | `sim_user_namespaces_off_refuses`, `real_id_map_unwritable_refuses` |
| F16-refusal-exit-code-not-71 | refusal exit code 1 | `real_landlock_abi_below_required_refuses` |
| F17-gid-map-reported-as-uid-map | a `gid_map` failure is reported as `uid_map` | 2 simulated tests |
| C00-noop-control | a comment | must survive |

Result: `python3 falsify.py` on this tree: filled after the falsify run.
A skipped (`ignored`) test is `NOT RUN`, never a pass.
F19 (skip `CLONE_NEWPID`) is caught because the probe's `nspid` is a
host pid. F23-F26 catch the #338 review gaps. F27-F29, F31 and F32
catch the #355 / #357 review gaps. F33-F35 catch the r3 residuals:
inherited fds, a lying kernel that accepts a right, and close-pipe
without `execve`.

## Not covered here

- aarch64 and Jetson: NOT RUN. `cargo check --target aarch64-unknown-linux-gnu --all-targets`
  is a compile check only. Nothing was executed for aarch64. A 5.15-class
  Jetson kernel cannot express `truncate` or `ioctl_dev`, so the guard
  refuses every provider and names those rights. That is not a board
  measurement.
- Real provider binaries: NOT RUN. The stand-in is the static probe. A
  dynamically linked provider needs Landlock read rules for its loader and
  libraries. This lab grants none.
- Mount, network and IPC namespaces: NOT RUN. They are not layers of this
  guard. The PID namespace is a layer; the real-kernel signal and nspid
  tests above cover it.
- File descriptor inheritance: covered. `close_fds` closes every fd except
  stdin, stdout, stderr and the fault pipe. An inherited pre-confine pty
  is gone before `execve`, so `TIOCGWINSZ` on that fd is `EBADF`.
- Start proof: EOF on the fault pipe is not enough. The parent samples
  `/proc/<provider pid>/exe` (device and inode) against the expected
  binary while that process is alive. Closing the pipe without `execve`
  is a refusal. A static binary that writes nothing is a start only when
  that identity matches.

## How `lab/linux-confine` (PR #296) could plug in

PR #296 has a C launcher, `helper/setup.c`, that does most of the same calls
in one forked child. It calls `unshare(CLONE_NEWUSER)` and writes the maps,
then creates mount, network, IPC and PID namespaces. It clears the ambient set
and calls `capset`, sets `no_new_privs`, applies one Landlock ruleset and
installs a seccomp allow-list. It refuses when Landlock, seccomp or user
namespaces are missing.

There are two ways to join it to this guard:

1. Port its policy into the trait. Each of its calls becomes one `Kernel`
   method, which is the shape `RealKernel` has now. Its seccomp allow-list
   replaces `seccomp::filter()` through `Plan`. Its mount, network and IPC
   namespaces become new steps in a new layer of `confine`. Then the simulated
   rows and the falsifiers here also cover its steps.
2. Wrap it as a backend. A `LinuxConfineKernel` implements `spawn_confined`
   by running `setup` with its policy file, and maps each refusal line to a
   `Fault` (for example "user namespaces are turned off" becomes
   `Step::Unshare`). Its per-step methods are not callable on their own, so
   the step order stays in `setup.c`. The simulated proofs here would then
   not cover it.

Option 1 keeps one guard and one refusal format. Before either option, two
differences need a decision. PR #296 maps uid 0 inside the namespace, and this
lab maps the caller's own uid. PR #296 does not call `PR_CAPBSET_DROP`, so the
bounding set of its provider stays full. This lab drops it, and
`real_confined_provider_has_every_layer` reads `CapBnd` 0 from the running
provider.
