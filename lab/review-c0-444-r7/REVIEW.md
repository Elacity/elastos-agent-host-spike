# Independent adversarial review r7 of C0 (#444)

Independent adversarial review r7 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/444
(C0 Linux fail-closed confinement, dumpable / ptrace claim) at `57cbd4af`.

Draft only. Do not merge this review PR. This folder is the only tree
this session writes. `lab/fail-closed-linux/` was left as the author
wrote it. Branches `cursor/c0-dumpable-ptrace-c084` (#444) and
`cursor/fail-closed-linux-0b95` (#307) were not pushed. The public
Elacity repo was not touched.

Read first: r6 review PR
https://github.com/Elacity/elastos-agent-host-spike/pull/440
at `13447927`. r6 leftover: dumpable stayed 1; a same-uid host
`PTRACE_ATTACH` and `/proc/<pid>/mem` worked. #444 claims that
leftover is closed.

```text
Lane:           lab/review-c0-444-r7
Reviewed PR:    Elacity/elastos-agent-host-spike#444
Head:           57cbd4af261ebecaa5fbfd7d19b2dd57cc70d7f0
Base:           cursor/fail-closed-linux-0b95 (#307)
Tree:           /workspace  (branch cursor/review-c0-444-r7-cb37)
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351),
                Landlock ABI 6, uid 1000, no Yama ptrace_scope,
                perf_event_paranoid=2
Aarch64:        qemu-system TCG, Alpine virt 6.18.58, ABI 7
                label: emulated CPU. Never native ARM.
Jetson stand-in: qemu-system TCG, Alpine virt 5.15, ABI 1
                label: emulated 5.15 kernel. Not a Jetson board.
Reviewer:       Cursor Grok (xAI family; author of #444 was Claude)
```

## Plain English

The official #444 claims hold on the rows they test. On this host,
`real_same_uid_host_cannot_ptrace_or_read_mem` is green: after start,
`PR_SET_DUMPABLE(1)` is EPERM, same-uid `PTRACE_ATTACH` of the
provider is EPERM, and `/proc/<provider>/mem` is root-owned and
EACCES. `falsify.py` is 37/37 CAUGHT. C00 survived with 63 tests
(9+22+32). F40 and F41 are CAUGHT.

That row does not close same-uid memory access. A 1:1 unprivileged
user namespace sets `ns->owner` to the caller's euid. Every same-uid
host process then has `CAP_SYS_PTRACE` in that namespace (kernel
`cap_capable` owner walk). Init as the exclusive tracer blocks
`PTRACE_ATTACH` only. `process_vm_readv` of the provider copied 8
bytes. `pidfd_getfd` of the provider duplicated fd 1. `perf_event_open`
on the provider returned a live fd at `perf_event_paranoid=2`.
`/proc/<provider>/maps`, `cmdline` and `status` stay readable.

The README claim that same-uid `PTRACE_ATTACH` of **init** is EPERM
is false on this host. Init is dumpable on purpose so the parent can
read `/proc/<init>/task/init/children`. A same-uid host attached init
(`ptrace_attach ok`). Injecting `PTRACE_DETACH` of the host provider
pid into init returned `rax=-3` (`ESRCH`): init sees the provider as
nspid 2. The provider stayed traced. SIGKILL of init still takes the
provider down (`EXITKILL`). SIGSTOP of init does not release the
provider.

Inside the sandbox, `process_vm_*`, `ptrace`, `io_uring_setup`,
`userfaultfd`, `perf_event_open`, x32 `prctl`, and a child `execve`
of a setuid-less helper are EPERM. `pidfd_getfd` of init is not on
the deny-list and succeeded.

**VERDICT: FIX**

## Re-run of the claimed suites

From `/workspace/lab/fail-closed-linux` at `57cbd4af`:

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          9 passed; 0 failed; 0 ignored
  simulated   22 passed; 0 failed; 0 ignored
  real_kernel 32 passed; 0 failed; 0 ignored
python3 falsify.py --jobs 2
  falsifiers: 37/37 caught; controls: 1/1 survived
  C00-noop-control: 63 tests passed
```

Evidence: `evidence/official-suite.txt`, `evidence/falsify.txt`.

Host counts match the author: **lib 9, simulated 22, real_kernel 32**.
Control suite is 63 tests (9+22+32).

## Verdicts on the claimed leftovers

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 9, simulated 22, real_kernel 32, 0 ignored | **HOLDS** on x86_64 ABI 6 | `evidence/official-suite.txt` |
| C0-T2 | falsify 37/37 caught, C00 survives 63 tests | **HOLDS** | `evidence/falsify.txt` |
| C0-T3 | same-uid ptrace and `/proc/<pid>/mem` closed via dumpable 0 | **PARTIAL** | provider `PTRACE_ATTACH` EPERM and `/proc/<pid>/mem` EACCES **HOLD**. Host `process_vm_readv` copied 8 bytes. Host `pidfd_getfd` duplicated fd 1. |
| C0-T4 | seccomp allows `PR_SET_DUMPABLE` only with value 0 | **HOLDS** | `prctl_dumpable_1 errno=1`; high-32 alias `EINVAL`; x32 `EPERM`; F41 CAUGHT |
| C0-T5 | execute-only granted binary | **HOLDS** | F40 CAUGHT; first launch `chmod 0111`s the granted path |
| C0-T6 | init traces the provider | **HOLDS** as exclusive-tracer for `PTRACE_ATTACH` | `TracerPid` is init; host attach of the provider is EPERM |
| C0-T7 | same-uid `PTRACE_ATTACH` of init is EPERM | **DOES NOT HOLD** | `ptrace_attach ok` on init. Official row never calls `assert_ptrace_and_mem_refused` on init |
| C0-T8 | bind-mount / Jetson / 9p / Landlock TCP / `SCOPE_SIGNAL` NOT RUN or NOT COVERED | **HONEST** | see below |

## Plant table (re-run)

| Plant | Result | Named test(s) that failed |
| --- | --- | --- |
| F01-fallback-restarts-unconfined | CAUGHT | sim user-ns + landlock-missing; real user-ns + landlock ABI |
| F02-cli-fallback-runs-unconfined | CAUGHT | real user-ns, seccomp, landlock ABI |
| F03-child-execs-after-refusal | CAUGHT | sim every-step + capset; real capset + ruleset |
| F04-userns-error-ignored | CAUGHT | sim + real user-ns |
| F05-uid-map-error-ignored | CAUGHT | sim + real id-map |
| F06-capset-error-ignored | CAUGHT | sim + real capability |
| F07-bounding-set-not-dropped | CAUGHT | sim + real confined-layers |
| F08-no-new-privs-error-ignored | CAUGHT | sim + real no_new_privs |
| F09-seccomp-error-ignored | CAUGHT | sim + real seccomp |
| F10-landlock-missing-tolerated | CAUGHT | sim + real landlock-missing |
| F11-abi-floor-off-by-one | CAUGHT | sim + real extra-floor ABI |
| F12-restrict-self-error-ignored | CAUGHT | sim + real ruleset |
| F13-socket-allowed | CAUGHT | real confined-layers |
| F14-storage-rule-covers-parent | CAUGHT | real confined-layers |
| F15-refusal-omits-provider | CAUGHT | sim user-ns; real id-map |
| F16-refusal-exit-code-not-71 | CAUGHT | real landlock ABI |
| F17-gid-map-reported-as-uid-map | CAUGHT | 2 simulated |
| F18-missing-right-silently-passed | CAUGHT | 4 simulated ABI rows |
| F19-pid-unshare-skipped | CAUGHT | real confined-layers + signal-host |
| F23-sim-ignores-access-mask | CAUGHT | sim access-mask |
| F24-extra-floor-hides-missing-right | CAUGHT | sim + real extra-floor-names-right |
| F25-empty-pipe-reported-as-start | CAUGHT | lib ConfineReady; real ConfineReady |
| F26-test-extra-right-ignored | CAUGHT | lib + sim + real extra-right |
| F27-helper-survives-as-returned-pid | CAUGHT | real SIGKILL + confined-layers |
| F28-first-child-exit-tears-down | CAUGHT | real daemonize |
| F29-init-does-not-reap-all | CAUGHT | real orphan-grandchild |
| F31-lying-abi-probe-skipped | CAUGHT | sim + real lying-ABI |
| F32-ioctl-dev-dropped-from-handled | CAUGHT | real confined-layers |
| F33-inherited-fds-left-open | CAUGHT | real inherited-pty |
| F34-enforcement-self-test-skipped | CAUGHT | sim + real lying-enforcement |
| F35-close-pipe-reported-as-start | CAUGHT | real close-pipe |
| F36-memfd-execveat | CAUGHT | memfd execveat + procfd + granted-path |
| F37-stdio-pty | CAUGHT | real stdin-pty |
| F38-stdio-socket | CAUGHT | real stdin-socket |
| F39-execve-after-start | CAUGHT | granted-path + memfd procfd |
| F40-dumpable-prctl-skipped | CAUGHT | real same-uid ptrace/mem |
| F41-dumpable-reenable-allowed | CAUGHT | real same-uid ptrace/mem |
| C00-noop-control | SURVIVED | 63 tests passed |

No plant is a false-FAIL. F40's name says "prctl" but the plant skips
`chmod 0111` of the granted path, not `PR_SET_DUMPABLE` in `exec()`.
That still fails the mem-owner half of the official row, so the plant
is a real catch of execute-only, not a false-FAIL.

## New hunts (this session)

Live against the built `fcl-launch` at this head. Evidence:
`evidence/attacks.json`, `evidence/attacks.stdout.txt`.

| Attack | Result | Notes |
| --- | --- | --- |
| inside `process_vm_readv` / `writev` | **CAUGHT** | both `errno=1` |
| inside `pidfd_getfd` of init | **SURVIVED** | `pidfd_open_parent ok`, `pidfd_getfd_parent ok`. Not in `DENIED` |
| child exec of a setuid-less helper, then ptrace | **CAUGHT** | `child_exec_self errno=1`; `ptrace_* errno=1` |
| `/proc/self` and `/proc/1` `{environ,maps,fd,mem}` from inside | **CAUGHT** | all `errno=13` (Landlock / dumpable) |
| `PR_SET_DUMPABLE` / high-32 alias / x32 ABI | **CAUGHT** | `errno=1`, `EINVAL` (22), `errno=1` |
| `io_uring_setup` | **CAUGHT** | `errno=1` |
| `userfaultfd` | **CAUGHT** | `errno=1` |
| inside `perf_event_open` | **CAUGHT** | `errno=1` |
| host `process_vm_readv` of the provider | **SURVIVED** | copied 8 bytes |
| host `process_vm_writev` of the provider | **SURVIVED** (permission) | `errno=14` (`EFAULT`), not `EPERM`. Access check passed; the first map was not writable |
| host `process_vm_readv` of init | **SURVIVED** | copied 8 bytes. Init is dumpable |
| host `pidfd_getfd` of the provider | **SURVIVED** | `pidfd_open ok`, `pidfd_getfd ok` |
| host `pidfd_getfd` of init | **SURVIVED** | same |
| host `PTRACE_ATTACH` of the provider | **CAUGHT** | `errno=1` |
| host `PTRACE_ATTACH` of init | **SURVIVED** | `ptrace_attach ok`. Claim in the #444 body and README is false |
| host `perf_event_open` of the provider | **SURVIVED** | live fd at `perf_event_paranoid=2` |
| host `/proc/<provider>/{environ,maps,fd,mem}` | **PARTIAL** | `mem`/`environ`/`fd` EACCES; `maps`, `cmdline`, `status` readable. `mem_uid=0`. `TracerPid` is init |
| host `/proc/<init>/{environ,maps,fd,mem}` | **SURVIVED** | `environ`/`maps`/`cmdline`/`status` readable. `mem_uid=1000`. `read_mem` is `EIO` at offset 0 after a successful open |
| SIGKILL init | **CAUGHT** | provider gone (`still_alive=0`, `other_alive=0`). Init death does not leave an untraced live provider |
| SIGSTOP init, then attach the provider | **CAUGHT** | provider stays alive and stays unattachable (`ptrace_attach errno=1`) |
| core dump (`SIGQUIT`) | **CAUGHT** | `get_dumpable=0`; no new core file |
| init confused-deputy (attach init, inject `PTRACE_DETACH`) | **PARTIAL** | `confuse_attach_init ok`; `confuse_detach_rax=-3` (`ESRCH` on the host pid); provider attach still EPERM |
| race before `set_not_dumpable` | **SURVIVED** | during the pre-exec window, `/proc/<provider>/mem` opened (`open_mem ok`). After `ready`, that open is EACCES. Attach of the provider stayed EPERM (init already attached) |
| bind-mount of the granted path | **NOT RUN** | `mount` exit 32 (this uid) |
| false-FAIL: require init `/proc/mem` EACCES | **FALSE-FAIL-IF-REQUIRED** | init must stay dumpable for `/proc/<init>/task/init/children` |

### Why host `process_vm_readv` survives

`PR_SET_DUMPABLE(0)` makes `/proc/<pid>/mem` root-owned. The official
row checks that file and `PTRACE_ATTACH`. It does not call
`process_vm_readv`.

The helper's `unshare(CLONE_NEWUSER)` plus a 1:1 uid map makes
`user_ns->owner` the host euid. `cap_capable` then grants every
same-uid host process every capability in that namespace, including
`CAP_SYS_PTRACE`. Dumpable 0 therefore cannot refuse
`ptrace_may_access` for a same-uid peer. Init as tracer only consumes
the single-tracer slot. `process_vm_readv` and `pidfd_getfd` do not
need that slot.

An unprivileged userns cannot map a different owner kuid. Yama is
absent on this host. Those are the two ways the kernel would hide
this path. Neither is this guard.

## Minimal patches

Not applied. The #444 tree was not edited.

1. `patches/0001-deny-pidfd-getfd.txt` — add `SYS_pidfd_open` and
   `SYS_pidfd_getfd` to `DENIED`. Closes the inside-sandbox survivor
   only.
2. `patches/0002-test-host-process-vm-and-init-attach.txt` — extend
   `real_same_uid_host_cannot_ptrace_or_read_mem` with
   `process_vm_readv` and `pidfd_getfd` of the provider, and either
   assert init attach or drop that sentence from the README. The new
   asserts fail on this head. That is the falsifier.

Parent-traces-init would close the init-attach claim only. It would
not close host `process_vm_readv` of the provider.

## aarch64 execution (emulated CPU)

qemu-system aarch64 TCG, Alpine virt 6.18.58. Guest label:

```text
LABEL=aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
native=0
jetson=0
emulated_cpu=1
landlock_abi=7
```

Guest finished. 9p loaded, then `9pnet_virtio: no channels available
for device evidence`. RESULTS reconstructed from `qemu-console.txt`.

```text
lib          9 passed; 0 failed; 0 ignored
simulated   22 passed; 0 failed; 0 ignored
real_kernel 32 passed; 0 failed; 0 ignored
```

`real_same_uid_host_cannot_ptrace_or_read_mem` ok.
`real_per_right_floor_refuses_on_this_kernel` ok (ABI 7 start half).

Evidence: `evidence/aarch64-qemu-system-6.18/`. Kernel sha256
`d1876369b061ef3bc33314f490240efcd32b031393cb34c6f81134fa862fe472`.

Never native ARM. Never Jetson.

## Jetson ABI-1 stand-in (emulated 5.15 kernel)

Same qemu-system TCG, Alpine virt 5.15.208. Label:

```text
LABEL=emulated 5.15 kernel under qemu-system TCG (not Jetson)
landlock_abi=1
```

Guest finished. 9p failed (`Unknown symbol __fscache_*`). RESULTS
reconstructed from `qemu-console.txt`.

```text
provider=did-provider exit=71
  cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)
provider=wallet-provider exit=71
  cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)
provider=model-provider exit=71
  cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)
suite=abi1 passed=3 failed=0 status=PASS
```

Author claim HOLDS on this emulated 5.15 kernel. It does not prove
tegra 5.15.148, JetPack LSM config, or real provider binaries.

Evidence: `evidence/aarch64-qemu-5.15/`. Kernel sha256
`b439cfd5003d74d851da95efd0f8befe17ff3943d8bed079d531701a1b61c242`.

## Exact counts per platform

| Platform | lib | simulated | real_kernel | notes |
| --- | --- | --- | --- | --- |
| Linux x86_64, kernel 6.12.94+, ABI 6 | 9 | 22 | 32 | official claim holds; new host escapes survive |
| aarch64 emulated CPU, kernel 6.18, ABI 7 | 9 | 22 | 32 | extra-right start half ok |
| emulated 5.15 kernel, ABI 1 | n/a | n/a | n/a | 3/3 providers exit 71 naming truncate and ioctl_dev |
| Real Jetson | NOT RUN | NOT RUN | NOT RUN | still needed |

## Not covered (honest)

- Host bind-mount of the granted path: **NOT RUN** (`mount` exit 32).
- Real Jetson board: **NOT RUN**.
- Guest 9p evidence mount: **NOT RUN**. 6.18 loaded 9p then had no
  virtio channel (`evidence_mount=console-only`). 5.15 failed
  `insmod` of 9p (`__fscache_*` missing). Results from the qemu
  console.
- Landlock TCP bind/connect: **NOT COVERED**. Seccomp denies `socket`
  first.
- `LANDLOCK_SCOPE_SIGNAL` self-test: **NOT COVERED**. The self-test
  child shares the provider PID namespace.

## False-FAIL cases

- Requiring init `/proc/mem` EACCES would false-FAIL the identity
  check. Init stays dumpable so the parent can read
  `/proc/<init>/task/init/children`.
- SIGKILL of init killing the provider is `PTRACE_O_EXITKILL` and
  the PID namespace working, not a confinement hole.
- `process_vm_writev` `EFAULT` is not a denial. Calling that CAUGHT
  would be a false-FAIL of the access check.
- F40 skipping `chmod` rather than `PR_SET_DUMPABLE` is still a real
  catch of execute-only. Treating F40 as "the prctl plant" would
  misread the plant, not false-FAIL the suite.

## Exact commands

```bash
export CARGO_TARGET_DIR=/workspace/lab/fail-closed-linux/target
export CARGO_BUILD_BUILD_DIR=/workspace/lab/fail-closed-linux/target/build
export RUST_TEST_THREADS=2
export CARGO_INCREMENTAL=0
cd /workspace/lab/fail-closed-linux
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 falsify.py --jobs 2

export FCL_SRC=/workspace/lab/fail-closed-linux
export FCL_LAUNCH=/workspace/lab/fail-closed-linux/target/debug/fcl-launch
lab/review-c0-444-r7/run.sh
FCL_SRC=/workspace/lab/fail-closed-linux lab/review-c0-444-r7/run-aarch64-guest.sh full
FCL_SRC=/workspace/lab/fail-closed-linux lab/review-c0-444-r7/run-aarch64-guest.sh abi1
```

## This folder

| Path | Why |
| --- | --- |
| `REVIEW.md` | this report |
| `README.md` | pointer |
| `attack.py` | live hunts against the built `fcl-launch` |
| `run-aarch64-guest.sh` | qemu-system TCG guest (emulated CPU / emulated 5.15) |
| `standins/hunter.c`, `payload.c`, `host-attacks.c` | stand-ins |
| `patches/` | minimal patches, not applied |
| `evidence/` | official suite, falsify, attacks, guests |

## Principles

- 3: after start the provider cannot `ptrace` or `process_vm` from
  inside. A same-uid host can still `process_vm_readv` and
  `pidfd_getfd` the provider. Init is attachable.
- 11: a later `PR_SET_DUMPABLE(1)` is EPERM. Dumpable 0 plus an
  exclusive tracer is not a closed host-memory story on a 1:1
  userns.
- 12: the README says init attach is EPERM. The official row does
  not test init. The host attach of init succeeded.

DeepSeek: none.

## Next

Keep #444 draft. Do not merge. Add the two patches or drop the
over-claim that same-uid host memory access is closed. Name host
`process_vm_readv` / `pidfd_getfd` as a leftover of the 1:1 userns
owner grant. Run the same rows on a real Jetson board.

**VERDICT: FIX** at `57cbd4af`. Official 9/22/32 and falsify 37/37
hold. Same-uid host `process_vm_readv` of the provider copied 8
bytes. `pidfd_getfd` of the provider succeeded. Init attach is not
EPERM. Bind-mount, real Jetson, 9p, Landlock TCP and
`LANDLOCK_SCOPE_SIGNAL` stay NOT RUN / NOT COVERED.
