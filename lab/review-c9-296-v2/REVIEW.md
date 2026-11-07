# Adversarial review of PR #296 C9 fixes (v2)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`.

```text
Lane:         lab/review-c9-296-v2
Branch / PR:  cursor/review-c9-296-v2-94b0  https://github.com/Elacity/elastos-agent-host-spike/pull/349
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         0785eecd4e40943adc93c455363a0bff4675cba8
Parent:       c0e22413efd8e76444a3f6539e31750d05dc6273
Tree:         /tmp/wt/linux-confine-296-v2 (detached, fetched origin/cursor/linux-confine-e156)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64 exec: NOT RUN
Jetson:       NOT RUN
```

C9 wording used here is the same as draft PR #326: namespaces, capabilities,
seccomp and Landlock, with permitted and denied rows per platform. B4 is the
permission-model table. The Linux map in
`capsules/wallet-provider/CONFINEMENT-LINUX.md` says the filter refuses a new
process and every `socket` and `socketpair`.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| confine 25 tests, providers 4, falsifiers 5/5, clippy clean | **HOLDS** | Commands below. Confine `25 passed; 0 failed; 0 ignored`. Providers `4 passed; 0 failed; 0 ignored`. `F-LC-SOCKET`, `F-LC-CAPBND`, `F-LC-BLOCK`, `F-LC-STORAGE`, `F-LC-PROVIDER-SOCKET` each printed `CAUGHT`. Clippy exit 0. |
| Only thread clone is allowed; clone3 returns ENOSYS | **HOLDS** on this x86_64 kernel | Extra probe through a freshly compiled standing `lc-setup`: `clone(SIGCHLD)`, `clone(CLONE_VM\|SIGCHLD)`, `clone(CLONE_VFORK\|CLONE_VM\|SIGCHLD)`, `fork`, and `vfork` returned errno 1. `clone(CLONE_THREAD\|…)` returned `ok`. Both `clone3` forms returned errno 38 (`ENOSYS`). Unconfined, those process forms succeeded. |
| `socketpair(AF_INET)` is refused | **HOLDS** | Provider filter: errno 1. Standing test also requires unconfined `socketpair(AF_INET)` errno 95 (`EOPNOTSUPP`). Extra probe: `AF_INET6` and `AF_NETLINK` pairs also errno 1. |
| `socketpair(AF_UNIX)` stays; named C9 departure | **HOLDS** as a named departure; **WEAK** against B4 | The pair succeeded and carried bytes inside the process. `connect`, `bind`, and `sendmsg` on that pair returned errno 1. `socket(AF_UNIX)` returned errno 1. The pair is intra-process only on this filter. B4 still says deny every `socketpair`. C9 cannot be booked as matching that row. |
| aarch64 skip is ignored, never a pass | **HOLDS** | `cargo test --test aarch64`: `0 passed; 0 failed; 1 ignored` with reason `needs aarch64-linux-gnu-gcc and qemu-aarch64; Jetson execution is NOT RUN`. `--ignored` panicked: `This ignored test must not count as a pass.` |
| aarch64 path compiles (`cargo check --target aarch64-unknown-linux-gnu`) | **WEAK** | That check exited 0. `build.rs` still compiles the C helpers with host `cc`. The ignored test is the one that would cross-compile `setup.c`. Real aarch64 execution is NOT RUN. |
| Six withheld storage rights are Landlock `EACCES`; REFER is `EXDEV` | **WEAK** | Confined probe: `make-sym`, `make-fifo`, `make-sock`, `make-char`, `make-block`, `ioctl-dev` errno 13; `refer` errno 18; `refer-mkdir` `ok`. Same-test unconfined success exists for four of those seven (`make-sym`, `make-fifo`, `make-sock`, `refer`). `make-char` / `make-block` unconfined are errno 1 (`EPERM`, no `CAP_MKNOD`). `ioctl(/dev/null, 0)` unconfined is errno 25 (`ENOTTY`). Those three confined `EACCES` rows are still Landlock-shaped, because a cap or `ENOTTY` failure would not satisfy `expect(..., Some(13), ...)`. |
| Denied provider rows carry errnos and a positive control | **HOLDS** | Did / wallet / model tables printed errno 13, 1, or 3 and an unconfined success on each denied row. Model `journal_corrupt: model run journal is unavailable` is printed as the provider mapping, not as the Landlock-read row. |
| Escape rows are named tests | **HOLDS** | `provider_filter_refuses_{ptrace,proc_self_mem,io_uring,bpf,unshare,setns,keyctl,dev_nodes,abstract_unix}` all passed on this head. |

## Claimed suite, this session

Worktree `0785eecd`. Provider debug binaries were built first.

```text
uname -a
# Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Mon Oct 26 16:24:23 UTC 2026 x86_64

python3 -c "import ctypes; print(ctypes.CDLL('libc.so.6').syscall(444, None, 0, 1))"
# 6

rustc --version
# rustc 1.91.0 (f8297e351 2025-10-28)

cargo build --manifest-path capsules/did-provider/Cargo.toml --bin did-provider
cargo build --manifest-path capsules/wallet-provider/Cargo.toml --bin wallet-provider
cargo build --manifest-path capsules/model-provider/Cargo.toml --bin model-provider
# each exit 0

cargo test --manifest-path lab/linux-confine/Cargo.toml --test confine -- --test-threads=1 --nocapture
# test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
# enforced abi=6 uid=0 caps=empty nnp=1 netns=lo storage_rights=0x41be

cargo test --manifest-path lab/linux-confine/Cargo.toml --test providers -- --test-threads=1 --nocapture
# test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.59s
# /proc/<pid>/status CapBnd: 0000000000000000 comm=did-provider (and wallet, model)

cargo test --manifest-path lab/linux-confine/Cargo.toml --test aarch64 -- --test-threads=1 --nocapture
# test aarch64_launcher_compiles ... ignored, needs aarch64-linux-gnu-gcc and qemu-aarch64; Jetson execution is NOT RUN
# test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s

cargo test --manifest-path lab/linux-confine/Cargo.toml --test aarch64 -- --ignored --exact aarch64_launcher_compiles --nocapture
# panicked at tests/aarch64.rs:17:9:
# aarch64 cross compiler is absent. NOT RUN. This ignored test must not count as a pass.
# test result: FAILED. 0 passed; 1 failed; 0 ignored

cargo check --manifest-path lab/linux-confine/Cargo.toml --target aarch64-unknown-linux-gnu --all-targets
# Finished `dev` profile ... in 4.63s
# exit 0

python3 lab/linux-confine/falsify.py
# F-LC-SOCKET CAUGHT
# F-LC-CAPBND CAUGHT
# F-LC-BLOCK CAUGHT
# F-LC-STORAGE CAUGHT
# F-LC-PROVIDER-SOCKET CAUGHT
# exit 0

cargo clippy --manifest-path lab/linux-confine/Cargo.toml --all-targets -- -D warnings
# Finished `dev` profile ... in 2.19s
# exit 0
```

`aarch64-linux-gnu-gcc` and `qemu-aarch64` are absent on this VM.

## Extra process and socketpair probe

`probe.c` is freestanding. It was launched through a standing `lc-setup`
compiled from `0785eecd` `helper/setup.c` with host `cc` (sha256
`80b7f3a3b4794ba97a87dfa460e2f68bcf403e41f8df89dd17df742486e503ff`).

Unconfined, the process-creation rows succeeded: `clone-sigchld`,
`clone-vm-sigchld`, `clone-vfork`, `clone-thread`, `fork`, `vfork`,
`clone3-sigchld`, `clone3-thread`.

Provider filter:

```text
enforced abi=6 uid=0 caps=empty nnp=1 netns=lo storage_rights=0x41be
op=clone-sigchld result=refused errno=1 reason=clone refused
op=clone-vm-sigchld result=refused errno=1 reason=clone refused
op=clone-vfork result=refused errno=1 reason=clone refused
op=clone-thread result=ok reason=clone created a child
op=clone-thread-newuser result=refused errno=22 reason=clone refused
op=clone-thread-newnet result=refused errno=1 reason=clone refused
op=clone-thread-newpid result=refused errno=22 reason=clone refused
op=clone-thread-newns result=refused errno=22 reason=clone refused
op=fork result=refused errno=1 reason=fork refused
op=vfork result=refused errno=1 reason=vfork refused
op=clone3-sigchld result=refused errno=38 reason=clone3 refused
op=clone3-thread result=refused errno=38 reason=clone3 refused
op=socketpair-unix result=ok reason=socketpair AF_UNIX succeeded
op=socketpair-unix-io result=ok reason=pair carries bytes inside the process
op=socketpair-connect result=refused errno=1 reason=connect on the pair refused
op=socketpair-bind result=refused errno=1 reason=bind on the pair refused
op=socketpair-sendmsg result=refused errno=1 reason=sendmsg on the pair refused
op=socketpair-inet result=refused errno=1 reason=socketpair AF_INET refused
op=socketpair-inet6 result=refused errno=1 reason=socketpair AF_INET6 refused
op=socketpair-netlink result=refused errno=1 reason=socketpair AF_NETLINK refused
op=socket-unix result=refused errno=1 reason=socket AF_UNIX refused
op=socket-inet result=refused errno=1 reason=socket AF_INET refused
```

The filter allows any `clone` whose flags include `CLONE_THREAD`. The
namespace-plus-thread combos then hit the kernel (`EINVAL` 22, or `EPERM` 1
for `CLONE_NEWNET`). Unconfined, those same combos failed the same way. That
is not a new process on this kernel.

`clone3` is `ENOSYS` for the thread form as well. A caller that uses only
`clone3` cannot create a thread. glibc/Tokio that fall back to
`clone(CLONE_THREAD)` can.

The short probe filter still refuses `clone-thread` and `socketpair-unix`
(errno 1). `clone3` on the short filter is errno 1, not 38: the short list
has no `clone3` special case.

`AF_UNIX` `socketpair` is a connected pair inside one process. `socket()`,
`bind`, `connect`, and `sendmsg` stay refused, so the pair does not become a
listen or connect path to a host name. That is the Tokio use. It is still a
C9 / B4 departure: the Linux map refuses every `socketpair` by number.

## Landlock withheld rights

`withheld_storage_rights_are_landlock_eacces` passed. The confined probe
printed errno 13 on the six `EACCES` rows and errno 18 on `refer`.
`refer-mkdir` was `ok` (granted `MAKE_DIR`).

Unconfined shipped `lc-probe` on this uid:

```text
op=make-sym result=ok
op=make-fifo result=ok
op=make-sock result=ok
op=make-char result=refused errno=1
op=make-block result=refused errno=1
op=refer result=ok
op=ioctl-dev result=refused errno=2   # no planted .lc-char outside the launcher
```

Separate host calls: `os.mknod` char/block errno 1; `ioctl(/dev/null, 0)`
errno 25. The standing test asks unconfined success only for `make-sym`,
`make-fifo`, `make-sock`, and `refer`. The other three confined `EACCES`
rows still fail if the errno is 1 or 25, so they are not a generic "any
error" pass.

## Provider denied rows

| Provider | Denied row | errno this session | Positive control printed |
| --- | --- | --- | --- |
| did | write / read outside | 13 | unconfined read of the outside file |
| did / wallet / model | socket | 1 | unconfined `socket(AF_INET)` |
| did / wallet / model | exec a copy | 13 | unconfined exec of the copy |
| did / wallet / model | signal host pid | 3 | unconfined `kill(host, 0)` |
| wallet | write / read outside | 13 | unconfined read of the outside file |
| model | write outside | 13 (witness) | unconfined read of the outside file |
| model | read outside | 13 (witness) | unconfined read of the outside file |

Model print: `provider mapping for the denied outside journal read stays journal_corrupt: model run journal is unavailable. That string is not the Landlock-read row.`

CapBnd on the three binaries was `0000000000000000`.

Those provider tests exec `capsules/<name>/target/debug/<name>` from this
tree. Installed release binaries, aarch64 provider binaries, and Jetson
binaries were NOT RUN.

## Mutants (worktree only, restored)

`python3 -I lab/review-c9-296-v2/mutants.py` edited the fetched tree, ran the
named test, then wrote the original file back. `git -C /tmp/wt/linux-confine-296-v2 status --short` was empty. `HEAD` stayed `0785eecd`.

| Plant | What changed | Named test | Result |
| --- | --- | --- | --- |
| `M-RV2-CLONE-VMLESS` | Invert the `CLONE_THREAD` `JSET` so process clone is allowed | `provider_filter_refuses_clone_process` | **CAUGHT**. `op=clone result=ok`. `left: "ok"` / `right: "refused"`. |
| `M-RV2-REFER` | Add `LANDLOCK_ACCESS_FS_REFER` to `LC_STORAGE_RIGHTS` | `withheld_storage_rights_are_landlock_eacces` | **CAUGHT**. `op=refer result=ok`. `left: "ok"` / `right: "refused"`. |
| `M-RV2-WRONG-ERRNO` | Process-clone denial returns `ENOSYS` instead of `EPERM` | `provider_filter_refuses_clone_process` | **CAUGHT**. `op=clone result=refused errno=38`. `left: Some(38)` / `right: Some(1)`. |
| `M-RV2-ANY-ERRNO` | `expect()` ignores errno, and process-clone denial returns `ENOSYS` | `provider_filter_refuses_clone_process` | **SURVIVED**. `test result: ok. 1 passed`. The errno column is load-bearing only in that one `assert_eq!`. |

The first three plants are the ones the standing suite is meant to catch. The
fourth shows what happens if a denied row accepts any errno: a wrong-errno
filter then stays green.

## What remains NOT RUN

- Jetson execution
- Real aarch64 execution (`qemu-aarch64` and `aarch64-linux-gnu-gcc` are absent)
- Cross-compile of `setup.c` / `probe.c` / `witness.c` with an aarch64 compiler
- Installed / release provider binaries
- A live x32 ABI socket
- `io_uring` as a spawn path (the setup call is refused; that is the row)

## Bookability

Anders's rule, as given for this review: a check counts only when its
complete journey, refusal evidence, and required reviews all pass.

C9 asks for those four layers with permitted and denied rows **per
platform**. This VM produced the x86_64 Linux rows, including the clone and
socketpair fixes from #326. aarch64 and Jetson still have no executed rows.
`socketpair(AF_UNIX)` on the shipping filter is a named departure from the
B4 / Linux-map deny of every `socketpair`.

**C9 cannot be booked.** Keep aarch64 and Jetson as NOT RUN until those
machines produce their own rows. Keep the Unix pair named as a departure
until Anders accepts it as the Linux mapping, or the model binary no longer
needs it.

## Next

#296 stays draft. This PR stays draft. Do not merge either.
