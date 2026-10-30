# fail-closed-linux: a launcher guard that refuses when a confinement layer cannot apply

Lab reference for the Linux half of M1 check C0, "Fail closed when confinement can't apply". The macOS half
exists in each provider's `CONFINEMENT.md` (`startup_is_refused_when_the_profile_cannot_be_applied`). This crate
is the Linux counterpart.

Status label: lab reference, not the Runtime. The Runtime half (launching the real did, wallet and model
providers through this guard) is future work in `elastos/`, outside this lane. This crate books no M1 check as
passed. Status and proof belong in the owning GitHub issue.

## What the guard does

`Guard::launch(provider, command)` applies every confinement layer **in the provider's own process, after `fork`
and before `exec`**. If any layer fails, the child stops before `exec`, `spawn` returns an error, and the guard
reports a `Refusal` that names the provider, the layer, the failing step and its system error. The provider image
never runs. There is no retry, no weaker mode and no "best effort" path.

Layers, in the order the guard applies them:

| Layer | Fault | Refusal reason (after `linux confinement refused: `) | Applied by |
| --- | --- | --- | --- |
| user namespace | `UserNamespaceOff` | `user namespaces are turned off` | `unshare(CLONE_NEWUSER)` |
| user namespace | `IdMapRefused` | `the user namespace id maps cannot be written` | `setgroups`, `gid_map`, `uid_map` (each id to itself) |
| capability drop | `CapabilityDrop` | `the capability set cannot be dropped` | bounding-set drop, then `capset` to empty |
| no_new_privs | `NoNewPrivs` | `no_new_privs cannot be set` | `prctl(PR_SET_NO_NEW_PRIVS)` |
| seccomp | `SeccompInstall` | `the seccomp filter cannot be installed` | `seccomp(SECCOMP_SET_MODE_FILTER)` |
| Landlock | `LandlockMissing` | `the kernel has no Landlock` | ABI query returns `ENOSYS` or `EOPNOTSUPP` |
| Landlock | `LandlockTooOld` | `the Landlock ABI cannot express the STORAGE_ROOT row (needs ABI 5, this kernel reports ABI N)` | ABI below the floor |
| Landlock | `LandlockApply` | `the Landlock ruleset cannot be applied` | ruleset create, `add_rule` or `restrict_self` fails |

The first five reasons are the lines already written in
`capsules/wallet-provider/CONFINEMENT-LINUX.md` ("When a primitive is missing"); a test reads that file and
requires each line (P10, P12). The id-map and ruleset reasons are new here: that design names no refusal for
them.

The Landlock floor is ABI 5 and a caller can only raise it. The STORAGE_ROOT row needs every filesystem right
the ABI reports: `REFER` (ABI 2), `TRUNCATE` (ABI 3) and `IOCTL_DEV` (ABI 5). A kernel that lacks one leaves that
right unrestricted, which is wider than the oracle, so the start is refused instead of weakened.

A fault crosses `fork` as the error number of the `pre_exec` failure (`Fault::to_wire`: a tag byte, the fault
code, the ABI the kernel reported, the errno). An ordinary `exec` failure has no tag and is a `LaunchError::Spawn`,
not a refusal; the provider did not run in either case.

## Standing alone

The crate depends on no confinement backend, and nothing here calls `lab/linux-confine/`. The seam is the `Kernel`
trait: seven async-signal-safe methods, one per kernel operation. `HostKernel` is the real implementation (`libc`,
x86-64 and aarch64). A backend that wants the same fail-closed discipline implements `Kernel` and calls
`Guard::with_kernel`.

The policy is data the caller gives the guard: `FsRules` (Landlock path rules) and a `SeccompProgram`.
`Policy::baseline` pairs the caller's path rules with a deny-list filter (every socket, `ptrace`, `process_vm_*`,
`pidfd_getfd`, `bpf`, `perf_event_open`; an x32 number or a foreign architecture is also refused). That filter is
a baseline for the tests and for the CLI, not the final policy; the confinement backend owns the real policy.

## Wrapping `lab/linux-confine`

This is a design. It is read from draft PR #296 (branch `cursor/linux-confine-e156`, head `dc948a70`). That lab was
read only: not built, not run, not edited. No code here calls it.

**The backend.** One C helper, `helper/setup.c`, applies every layer in one process and then executes the probe:
user namespace and id map, mount, network, IPC and PID namespaces, a Landlock ruleset, capability drop,
`no_new_privs`, Landlock enforce, a seccomp allow-list, `exec`. The Rust side writes a policy file, runs the helper
and parses its stdout. A refusal is one text line on stdout and exit status 2.

**The answer.** The helper stays the only process that applies layers. The guard wraps it from outside: it starts
the helper, owns the status channel, turns every backend failure into a `Refusal`, checks the backend's claim, and
never starts the provider itself. There are two reasons for this shape.

- Two appliers must not stack. The guard's Landlock rules name only the storage root and the provider. The helper
  opens its policy file and `/proc/self/uid_map`, so I expect it to refuse if it ran inside the guard's layers.
  This is read from the code, not run.
- A PID namespace needs a second `fork` after `unshare(CLONE_NEWPID)`. The helper does it (`setup.c` forks a
  grandchild). `Command::pre_exec` has no place for that fork.

What each side does next:

1. **Status channel (backend lane).** The helper reports on stdout, but a provider's stdout carries its own
   protocol, and exit status 2 is a legal provider status. The guard passes the helper a close-on-exec pipe. The
   helper writes one record on a refusal and nothing on success, so end-of-file means the `exec` happened.
   `close_high_fds` (descriptors 3 to 255) must skip that descriptor. `std` already reports a `pre_exec` failure
   to this crate the same way.
2. **A `Fault` for every reason (guard lane).** Each helper reason for user namespace, capability drop,
   `no_new_privs`, seccomp install, Landlock missing, Landlock ABI and Landlock ruleset maps to the `Fault` of the
   same name. The helper also refuses for the mount, network, IPC and PID namespaces and for a kernel with no
   seccomp. The guard needs a `Fault` for each. A reason the guard does not know is still a refusal. A failed
   `exec` of the provider is a `LaunchError::Spawn`, as in
   `a_failed_exec_after_every_layer_applied_is_a_spawn_error_not_a_refusal`.
3. **Check the claim (guard lane).** The helper prints `enforced abi=N uid=U caps=empty nnp=1 netns=lo` before it
   executes. A missing record, a missing field, or a value below the guard's Landlock floor is a refusal. One gap
   shows already: `setup.c` makes no `PR_CAPBSET_DROP` call, and this crate's confinement test requires `cap_bnd`
   to be 0, so the helper needs that step.
4. **Test with the harness already here (guard lane).** `launch_cli_under` and `deny_filter` in
   `tests/common/mod.rs` fail one real system call under an inherited filter. Pointed at the helper, they replace
   its `--block-landlock`, `--block-seccomp`, `--block-userns` and `--explain-abi` switches, which are test code
   inside the production binary. They also reach rows the backend's tests do not name: capability drop,
   `no_new_privs`, seccomp install, Landlock enforce and each namespace. Falsifier `F-FC12` (a silent unconfined
   fallback) applies to the wrap: with the helper stubbed to fail, the provider marker must not appear.
5. **One policy, from the oracle (decision for the owners).** The two crates give the storage root different
   rights. The backend grants eight (read file, read dir, write file, truncate, make regular file, make dir,
   remove file, remove dir). `FsRules::read_write_dir` grants every right except execute, which adds seven: make
   char, socket, fifo, block and symlink, `REFER` and `IOCTL_DEV`. PRINCIPLES 10 asks for one path, so the guard
   should take the backend's rights, which come from `confine.sb`. The backend's seccomp policy is an allow-list of
   eight system calls sized for a freestanding probe. A real provider needs a wider list, and this crate builds
   deny-lists only.

## The launcher CLI

```text
fcl-launch --provider <did-provider|wallet-provider|model-provider> --storage-root DIR [--read-exec DIR]... -- PROGRAM [ARG...]
```

It starts PROGRAM with every layer applied or refuses and prints the reason. Exit status: the provider's own
status after a start; 71 when the guard refuses (the status `sandbox-exec` gives when it cannot start a
provider); 70 for another start failure; 64 for a usage error. On a host that is not Linux it refuses with
`this host is not Linux` and exits 71.

## Tests

Run from the repository root:

```bash
cargo fmt --manifest-path lab/fail-closed-linux/Cargo.toml -- --check
cargo test --locked --manifest-path lab/fail-closed-linux/Cargo.toml
python3 -I lab/fail-closed-linux/falsify.py
```

Three kinds of evidence:

1. `tests/refusals.rs`: the guard against a simulated kernel. Each missing layer is injected alone, for all three
   providers. Each test checks the refusal's type, layer, reason text and system error; that the provider's marker
   file never appears; that nothing is left under the storage root; and the exact list of kernel calls the child
   made (a layer after the failing one must not run).
2. `tests/real_kernel.rs`, refusals: the launcher CLI runs under an **inherited seccomp filter that makes one real
   system call fail** (`unshare`, `capset`, `prctl(PR_CAPBSET_DROP)`, `prctl(PR_SET_NO_NEW_PRIVS)`, `seccomp`,
   `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`). That is how a container profile or an
   old kernel makes the call fail. No fake object sits between the guard and the kernel. The harness filter is
   built independently of the crate's own filter builder. A control run with a filter on a call the guard never
   makes shows the provider starts.
3. `tests/real_kernel.rs`, confinement: a started provider is shown to be confined. `NoNewPrivs` is 1, `Seccomp` is
   2, the effective, permitted, inheritable and bounding capability sets are empty, the user namespace differs
   from the parent's, a socket gets `EPERM`, and a write or `truncate` outside the storage root gets `EACCES`.
   `the_provider_runs_confined_or_is_refused_never_unconfined` holds on any Linux host: confined, or refused.

The stand-in provider (`src/bin/stand-in-provider.rs`) is not a real provider. It creates a marker file when its
image starts, which is the evidence that a provider ran.

## Falsifiers

`falsifiers.json` lists 27 entries; `falsify.py` plants each bug in a scratch copy (the working tree is never
edited) and requires every named test to fail at an assertion. A build failure or a test that did not run is not a
catch. `F-FC00` changes nothing and must survive, so the runner is shown not to call every run a catch. The shared
`examples/agent-host/falsify.py` has no entry for this crate, so this folder carries its own runner.

The runner gives each scratch copy its own target directory. Cargo names an artifact by a hash that does not
depend on the copy's path, so a shared directory lets one copy run a binary built from another copy's source. The
first run of this list hit exactly that (a baseline test failed on a clean copy) and the runner was fixed.

Each scratch copy also gets the repo's `rust-toolchain.toml`. A copy outside the repo would otherwise build with
rustup's default toolchain, and an offline cargo of another version cannot find the crates the pinned one cached.
On a fresh checkout every entry reported NOT RUN for that reason until the file was copied. The offline lookup
needs a warm cache, so run `cargo test --locked` once before the runner.

| Id | Bug planted | Row |
| --- | --- | --- |
| F-FC01 | ignore a user-namespace failure | user namespaces off |
| F-FC02 | ignore a failed id-map write | id maps |
| F-FC03 | ignore a failed capability drop | capability drop |
| F-FC04 | ignore a failed no_new_privs | no_new_privs |
| F-FC05 | ignore a failed seccomp install | seccomp |
| F-FC06 | treat no Landlock as the newest Landlock | Landlock missing |
| F-FC07 | accept any Landlock ABI | Landlock too old |
| F-FC08 | ignore a ruleset that cannot be applied | Landlock apply |
| F-FC09, F-FC10 | lower the floor; let a caller lower it | ABI floor |
| F-FC11 | a reason that names no primitive | reason text |
| F-FC12 | **silent fallback: start the provider again unconfined after any refusal** | never unconfined |
| F-FC13, F-FC14 | layer order changed; keep applying after a failure | order |
| F-FC15, F-FC16 | foreign architecture and x32 numbers pass the filter | seccomp program |
| F-FC17 | `socket` missing from the deny list | seccomp policy |
| F-FC18 | `TRUNCATE` not handled by the ruleset | Landlock rights |
| F-FC19 to F-FC23 | skip the bounding drop, `capset`, `no_new_privs`, the seccomp error check, `unshare` | host layers |
| F-FC24 | CLI prints a refusal but exits 0 | CLI |
| F-FC25, F-FC26 | refusal text loses the provider name, or the step and system error | reason text |

## Not covered

- The mount, network, PID and IPC namespaces that the Linux design lists. This guard has no slot for them yet.
  Network is covered by the seccomp socket refusal, not by an empty network namespace.
- Descriptors the provider inherits. Landlock does not check a descriptor opened before enforcement, so the
  launch must hand over only stdin, stdout and stderr. The design leaves that to Runtime work; the guard does not
  close descriptors.
- Real did, wallet and model provider binaries. Only the stand-in provider was launched.
- Hosts that create the user namespace but then withhold capabilities in it (for example an AppArmor profile that
  restricts unprivileged user namespaces). The capability drop would fail and the guard would refuse. No test ran
  on such a host.
- A Landlock rule for `PROVIDER_EXECUTABLE` alone. The tests give the dynamically linked stand-in read and execute
  on the loader directories as well. The design's open question about shared libraries stays open.
- A real-kernel proof of the id-map refusal (`IdMapRefused`). Only the simulated-kernel test covers it. The
  real-kernel harness fails one system call by number and first argument, and the maps are written with ordinary
  `openat` and `write` calls.
- A kernel older than the floor. The real-kernel "Landlock too old" test raises the floor one above the ABI this
  kernel reports. No kernel with an ABI below 5 was used.
- Any host or architecture other than the ones `LOG.md` names. The code compiles for aarch64, and no aarch64 test
  has run.
