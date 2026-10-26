# fail-closed-linux: a provider launch guard that fails closed (M1 C0 lab)

This lab proves one rule on Linux: a provider starts confined, or it does not
start. The guard runs in the provider's own process, after `fork` and before
`exec`. If any confinement step fails, `exec` does not run, and the guard
returns a refusal that names the provider, the layer, the step and the OS
error. The launcher CLI exits 71. There is no fallback path.

This is a lab model, not Runtime code. Runtime integration is separate work.

## The guard

`confine` in `src/lib.rs` applies five layers in this order. The first failed
step stops it.

| Layer | Steps | What the step does |
| --- | --- | --- |
| user-namespace | `unshare`, `uid_map`, `setgroups`, `gid_map` | `unshare(CLONE_NEWUSER)`, then maps the caller's own uid and gid to themselves |
| capabilities | `cap_last_cap`, `bounding_set`, `ambient_set`, `capset` | `PR_CAPBSET_DROP` for every capability up to `/proc/sys/kernel/cap_last_cap`, `PR_CAP_AMBIENT_CLEAR_ALL`, then `capset` to all zero |
| no_new_privs | `set_no_new_privs` | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| seccomp | `install_filter` | `seccomp(SECCOMP_SET_MODE_FILTER)` with the filter in `src/seccomp.rs` |
| landlock | `abi_probe`, `abi_floor`, `create_ruleset`, `storage_root_rule`, `executable_rule`, `restrict_self` | probes the kernel ABI, then requires every right the shared file profile needs (`truncate` at ABI 3, `ioctl_dev` at ABI 5). A missing right refuses and names the right and the ABI that first expresses it. The ruleset handles only bits that ABI knows. The storage grant is the eight-right mask (no `REFER`, no `ioctl_dev`, no special-file create). ABI 6 also sets `LANDLOCK_SCOPE_SIGNAL`. |

After the five layers, `execve` starts the provider with an empty environment.

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
errno, found ABI) and calls `_exit(71)`. If `exec` succeeds, the pipe closes
with no data. The child uses only data that `Plan` built before the fork, and
it makes only system calls: it does not allocate, lock or panic.

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

The real-kernel tests need unprivileged user namespaces, seccomp, and a
Landlock ABI that can express `truncate` and `ioctl_dev` (ABI 5 or above).

## Results on this host

Linux x86_64, kernel 6.12.94+, rustc 1.91.0, Landlock ABI 6.

| Suite | Tests |
| --- | --- |
| `lib` (unit) | 6 passed |
| `simulated` | 13 passed |
| `real_kernel` | 9 passed |

Each refusal row runs for `did-provider`, `wallet-provider` and
`model-provider` in both suites. A real-kernel row uses the real `fcl-launch`
binary and the guard's real system calls on this kernel. On some rows a
kernel rule makes the step fail. On the other rows the launcher inherits a
seccomp filter that makes one system call fail. In that case the kernel's
seccomp gives the errno, and the feature itself is present.

| Row | Simulated kernel | Real kernel | How the real step fails |
| --- | --- | --- | --- |
| user namespaces off | `sim_user_namespaces_off_refuses` (EPERM, ENOSPC) | `real_user_namespaces_off_refuses` | kernel rule: a parent user namespace with `max_user_namespaces` 0 gives ENOSPC; inherited filter: `unshare` gives EPERM |
| id maps cannot be written | `sim_id_maps_unwritable_refuses` (`uid_map`, `setgroups`, `gid_map`) | `real_id_map_unwritable_refuses` | kernel rule: a launcher binary with mode 0111 makes the process not dumpable, so opening `/proc/self/uid_map` gives EACCES |
| capability drop fails | `sim_capability_drop_failure_refuses` (all four steps) | `real_capability_drop_failure_refuses` | inherited filter: `capset` gives EPERM; `prctl(PR_CAPBSET_DROP)` gives EPERM |
| no_new_privs cannot be set | `sim_no_new_privs_failure_refuses` | `real_no_new_privs_failure_refuses` | inherited filter: `prctl(PR_SET_NO_NEW_PRIVS)` gives EPERM |
| seccomp cannot be installed | `sim_seccomp_install_failure_refuses` (EINVAL, ENOSYS) | `real_seccomp_install_failure_refuses` | inherited filter: `seccomp` gives ENOSYS |
| Landlock missing | `sim_landlock_missing_refuses` (ENOSYS, EOPNOTSUPP) | `real_landlock_missing_refuses` | inherited filter: `landlock_create_ruleset` gives ENOSYS or EOPNOTSUPP |
| Landlock ABI too old | `sim_landlock_abi_too_old_refuses` (ABI 1 to 4 name the missing right; ABI 6 with 7 required) | `real_landlock_abi_below_required_refuses` | kernel rule: `--require-landlock-abi` set to the host ABI plus 1 |
| Landlock ruleset cannot be applied | `sim_landlock_ruleset_unappliable_refuses` (all four steps) | `real_landlock_ruleset_unappliable_refuses` | kernel rule: 16 inherited Landlock domains make `restrict_self` give E2BIG; inherited filter: `restrict_self` gives EPERM |

The positive tests:

- `sim_confined_provider_starts_after_every_layer` checks the order of the
  six layers, one bounding drop per capability, and one exec.
- `real_confined_provider_has_every_layer` starts the probe and reads the
  running probe's `/proc/<pid>` from outside. It sees `NoNewPrivs: 1`,
  `Seccomp: 2`, `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` all zero,
  an identity `uid_map`, and a user namespace that differs from the test's.
  Inside, the probe sees EPERM on an inet socket and a unix socket, EACCES on
  a read and a write outside its storage root and on `/etc/passwd`, and a
  working write and read inside its storage root.

Two more checks: `sim_every_guard_step_failure_stops_before_exec` fails each
guard step in turn, and `sim_landlock_abi_floor_cannot_be_lowered` shows that
`--require-landlock-abi 3` on ABI 4 still refuses because `ioctl_dev` needs
ABI 5.

`sim_per_right_floor_for_each_abi` walks ABI 1 through 6 for each provider.
`sim_missing_right_is_never_silently_dropped` requires the named-right
refusal on ABI 1-4.

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
(`capsules/wallet-provider/CONFINEMENT-LINUX.md`). This lab unshares only
`CLONE_NEWUSER`. `unshare(CLONE_NEWPID)` in the already-forked child does
not put the provider itself in the new namespace; only later children enter
it. Isolating the provider needs a grandchild after that unshare, which
would change the fault-pipe pid contract. That second fork is a named gap,
not a silent skip of a Landlock right.

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
| F12-restrict-self-error-ignored | a `restrict_self` error is ignored | the ruleset row in both suites |
| F13-socket-allowed | `socket` removed from the seccomp deny-list | `real_confined_provider_has_every_layer` |
| F14-storage-rule-covers-parent | the Landlock storage rule names the parent directory | `real_confined_provider_has_every_layer` |
| F15-refusal-omits-provider | the refusal text drops the provider name | `sim_user_namespaces_off_refuses`, `real_id_map_unwritable_refuses` |
| F16-refusal-exit-code-not-71 | refusal exit code 1 | `real_landlock_abi_below_required_refuses` |
| F17-gid-map-reported-as-uid-map | a `gid_map` failure is reported as `uid_map` | 2 simulated tests |
| C00-noop-control | a comment | must survive |

Result: 18 of 18 caught, and the control survived with 28 tests passed.

## Not covered here

- aarch64 and Jetson: NOT RUN. `cargo check --target aarch64-unknown-linux-gnu --all-targets`
  is a compile check only. Nothing was executed for aarch64. A 5.15-class
  Jetson kernel cannot express `truncate` or `ioctl_dev`, so the guard
  refuses every provider and names those rights. That is not a board
  measurement.
- Real provider binaries: NOT RUN. The stand-in is the static probe. A
  dynamically linked provider needs Landlock read rules for its loader and
  libraries. This lab grants none.
- Mount, network, PID and IPC namespaces: NOT RUN. They are not layers of
  this guard. The PID namespace that would contain the provider is a named
  gap, recorded above.
- File descriptor inheritance: NOT RUN. The guard does not close descriptors
  that the provider inherits. Only the fault pipe is close-on-exec.
- If the child crashes before `exec` without writing a fault, the pipe is
  empty and `launch` reports a start. Nothing runs in that case.
  `std::process::Command` has the same limit.

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
   replaces `seccomp::filter()` through `Plan`. Its four extra namespaces
   become new steps in a new layer of `confine`. Then the simulated rows and
   the falsifiers here also cover its steps.
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
