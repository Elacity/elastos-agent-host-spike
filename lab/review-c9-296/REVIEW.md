# Adversarial coverage review of PR #296 (C9 / B4)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`.

```text
Lane:         lab/review-c9-296
Branch / PR:  cursor/review-c9-296-99c1  https://github.com/Elacity/elastos-agent-host-spike/pull/326
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         2dc3c565c6649d668f1e50efefeea7d964330f9c
Tree:         /tmp/wt/linux-confine-296 (fetched origin/cursor/linux-confine-e156)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64:      NOT RUN
Jetson:       NOT RUN
```

## C9 wording used here

The M1 check text (`milestones.json`) is not in this repo. The wording this
review holds the PR to:

> C9 requires namespaces, capabilities, seccomp and Landlock, with permitted
> and denied rows per platform.

B4 is the permission-model table. C9 is Linux enforcement of that table by
those four layers. The Linux map in
`capsules/wallet-provider/CONFINEMENT-LINUX.md` is the detailed C9 text the
lab says it implements: user, mount, net, IPC and PID namespaces; empty
capabilities; one seccomp filter; one Landlock ruleset; permitted storage
and in-memory rows; denied reads, writes, sockets, exec, signals and a new
process.

## How the probes work

`probe.c` is freestanding. `run.py` launches it three ways:

1. Unconfined. A must-deny row that is `ok` here is the falsifier: the probe
   can see a hole.
2. Through #296 `lc-setup` on the short filter (the freestanding probe path).
3. Through the same launcher with `mode=provider` (the filter the shipping
   binaries get).

`i386_probe.c` is a fourth launch. Unconfined it prints `i386-ran`. Under
`lc-setup` the process dies after the `enforced` line and the launcher exits
2, which is the arch-kill path.

`falsify.py` plants three bugs in this folder only:

- F-RV-UNCONFINED: the unconfined binary must show `socket-inet` as `ok`.
- F-RV-GRADE: a planted `op=socket-inet result=ok` must fail `grade()`.
- F-RV-SKIP: an `aarch64.rs` that `return`s on a missing tool must be
  reported as a skip counted as pass.

This session: `F-RV-UNCONFINED CAUGHT`, `F-RV-GRADE CAUGHT`, `F-RV-SKIP
CAUGHT`. Five unittest cases passed. The unconfined control showed 21
successes the probe can see.

Aarch64 and the Jetson stay NOT RUN. This runner does not register
`binfmt_misc` or qemu.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Real did, wallet, and model debug binaries run under the Linux profiles | holds | `cargo test --test providers` on this head: 4 passed. Each test execs `capsules/<name>/target/debug/<name>` through `lc-setup`. |
| 5–6 permitted and 5 denied rows each | holds on the provider tables; weak on the probe tables | Provider run this session: did 6/5, wallet 5/5, model 6/5. `tests/confine.rs` `profile_rows` prints wallet_contract names as permitted after the freestanding probe writes one file. Those named operations did not run. |
| CapBnd of the confined provider is 0 | holds | `confined_process_cap_bnd_is_zero`: `/proc/12158/status CapBnd: 0000000000000000 comm=did-provider`. Same zero on the three provider tables. |
| `--block-*` / `--explain-abi` compile only into `lc-setup-test` | holds | Production `lc-setup` strings have none of the four switches and answers `--block-landlock` with `unknown launch argument`. `lc-setup-test` contains all four and answers `--block-landlock` with `the kernel has no Landlock`. `F-LC-BLOCK` matches that split. |
| STORAGE_ROOT stays at eight Landlock rights, mask `0x41be` | weak | The enforced line is `storage_rights=0x41be` on both filters and on the three provider runs. `F-LC-STORAGE` only fails when that printed mask changes. `symlinkat` and `mknodat` are absent from the provider allow-list, so MAKE_SYM / MAKE_FIFO / MAKE_SOCK / MAKE_CHAR return seccomp `EPERM` and never reach Landlock. REFER via `linkat` returned `EEXIST` (17), not `EACCES`. |
| Denied rows prove denial by the intended layer | weak | Socket, host signal, and unbound exec match their layers (see below). Model `journal_corrupt` is the provider's "unavailable" code, not a named Landlock errno. `F-LC-SOCKET` mutates only the short filter. |
| A skipped or not-run test is not counted as passed | falsified | `tests/aarch64.rs` prints `aarch64 cross compiler is absent. NOT RUN` and `return`s. `cargo test --test aarch64` on this VM: `ok. 1 passed`. |
| Seccomp default action and arch filtering (x32 / i386) | holds on this kernel | Unknown syscall 999: unconfined `ENOSYS` (38), confined `EPERM` (1). x32 `socket` (`nr \| 0x40000000`): unconfined `ENOSYS`, confined `EPERM`. This VM has no x32 ABI, so a live x32 socket was NOT RUN. i386 `int $0x80` write runs unconfined (`i386-ran`) and dies after `enforced` under `lc-setup` (exit 2, no probe line). |
| Escape attempts listed below are refused | holds on the short filter; weak on the provider filter | Short filter: every must-deny row refused, plus `socketpair` and `clone(SIGCHLD)`. Provider filter: the same, except `socketpair(AF_UNIX)` and `clone(SIGCHLD)` succeed. |
| C9 wording (four layers + permitted and denied rows per platform) | weak | x86_64 has the four layers and rows. aarch64 is a skip counted as pass. Jetson is NOT RUN. The shipping filter allows a new process, which the C9 Linux map says the filter refuses. |

## Layer checks on the denied provider rows

| Row | Intended layer | This session | Verdict |
| --- | --- | --- | --- |
| socket | seccomp | Witness `errno=1`. Unconfined `socket(AF_INET)` is `ok`. Provider filter still denies `SYS_socket`. `F-LC-SOCKET` only flips the short filter. | holds for the short path; weak for the provider path |
| signal a host pid | PID namespace | `errno=3`, and `SYS_kill` is on both allow-lists. Unconfined `kill(host, 0)` is `ok`. | holds |
| exec a copy | Landlock | `errno=13`, and `SYS_execve` is allowed. Second start with `binary=copy` reports `exec of PROVIDER_EXECUTABLE failed errno=13`. | holds |
| did outside read/write | Landlock | Host plants a symlink under `STORAGE_ROOT`. Provider answers `Permission denied (os error 13)`. Unix mode on the outside file would allow the write. | holds |
| wallet outside read/write | Landlock | `init` with an outside `base_path` answers `Permission denied (os error 13)` on create/sync. Directories are mode `0700` for this uid. | holds |
| model outside write | Landlock, mapped by the provider | `journal_access_denied` is `journal_write_io` on `ErrorKind::PermissionDenied`. The outside journal is mode `0700` for this uid, so the `EACCES` is the kernel. | holds |
| model outside read | Landlock | `runs/` is replaced by a symlink. The answer is `journal_corrupt: model run journal is unavailable`, the provider's generic unavailable code. | weak |

## Escape probes

Unconfined successes the probe can see (21): `socket-inet`, `socket-unix`,
`socketpair`, `abstract-unix`, `ptrace`, `proc-self-mem`, `unshare-user`,
`unshare-net`, `keyctl`, `pidfd-open`, `process-vm-readv`, `dev-null`,
`dev-zero`, `sys-kernel`, `signal-host`, `make-sym`, `make-fifo`,
`make-sock`, `dotdot`, `refer`, `clone-process`.

Rows that fail both ways, so the probe cannot show a hole by success:
`userfaultfd` and `mount` (`EPERM` unconfined), `make-char` (needs
`CAP_MKNOD`), `dev-kcore` (host `EACCES`), `exec-unbound` (the copy in the
control is not executable). For those, a confined `ok` would still fail
`grade()`. `io_uring_setup` and `perf_event_open` return `EFAULT`
unconfined and `EPERM` confined, which is enough to show seccomp ran.

| Probe | Short filter | Provider filter |
| --- | --- | --- |
| ptrace | refused `EPERM` | refused `EPERM` |
| `/proc/self/mem` | refused `EACCES` | refused `EACCES` |
| mount | refused `EPERM` | refused `EPERM` |
| unshare (user, net) | refused `EPERM` | refused `EPERM` |
| setns | refused `EPERM` | refused `EPERM` |
| keyctl | refused `EPERM` | refused `EPERM` |
| bpf | refused `EPERM` | refused `EPERM` |
| io_uring_setup | refused `EPERM` | refused `EPERM` |
| perf_event_open | refused `EPERM` | refused `EPERM` |
| symlink / fifo / sock / char in storage | refused `EPERM` (seccomp) | refused `EPERM` (seccomp) |
| `..` / outside read | refused `EACCES` | refused `EACCES` |
| writable `/dev/null`, `/dev/zero` | refused `EACCES` | refused `EACCES` |
| signal host pid | refused `ESRCH` | refused `ESRCH` |
| abstract unix (`socket(AF_UNIX)`) | refused `EPERM` | refused `EPERM` |
| network (`socket(AF_INET)`) | refused `EPERM` | refused `EPERM` |
| `socketpair(AF_UNIX)` | refused `EPERM` | **ok** |
| `clone(SIGCHLD)` | refused `EPERM` | **ok** |
| x32 socket | refused `EPERM` | refused `EPERM` |
| unknown syscall 999 | refused `EPERM` | refused `EPERM` |
| i386 `int $0x80` | killed (exit 2) | not launched (same short helper) |

`clone(SIGCHLD)` under the provider filter is a new process, not a Tokio
thread. `CONFINEMENT-LINUX.md` says the filter admits the thread form of
`clone` and refuses a new process. The shipping allow-list has `SYS_clone`
and `SYS_clone3` with no flag check. That is the C9 process-creation gap.

`socketpair(AF_UNIX)` is the documented Tokio widening. `socket` itself stays
refused, including `AF_UNIX`, so an abstract name still cannot be bound.

## Skip counted as pass

```text
cargo test --manifest-path lab/linux-confine/Cargo.toml --test aarch64 \
  -- --exact aarch64_launcher_compiles --nocapture
# aarch64 cross compiler is absent. NOT RUN
# test result: ok. 1 passed
```

The PR body says the aarch64 cross build and `qemu-aarch64` check passed.
On a machine without those tools the standing test still reports `ok`.

## #296 suites rerun here

```text
cargo test --manifest-path lab/linux-confine/Cargo.toml --test confine \
  -- --test-threads=1 --nocapture
# 12 passed

cargo test --manifest-path lab/linux-confine/Cargo.toml --test providers \
  -- --test-threads=1 --nocapture
# 4 passed

cargo test --manifest-path lab/linux-confine/Cargo.toml --test aarch64 \
  -- --exact aarch64_launcher_compiles --nocapture
# 1 passed, body: NOT RUN
```

Provider binaries were built first:

```text
cargo build --manifest-path capsules/did-provider/Cargo.toml --bin did-provider
cargo build --manifest-path capsules/wallet-provider/Cargo.toml --bin wallet-provider
cargo build --manifest-path capsules/model-provider/Cargo.toml --bin model-provider
```

## Probe counts

| Kind | Count |
| --- | --- |
| Must-deny escape rows in `check.py` | 32 |
| Filter-split rows (`socketpair`, `clone-process`) | 2 |
| Separate i386 launch | 1 |
| Review falsifiers (`F-RV-*`) | 3 |
| Unittest cases | 5 |
| Unconfined successes the probe can see | 21 |
| #296 confine tests rerun | 12 |
| #296 provider tests rerun | 4 |

## Concrete fixes

1. Make `aarch64_launcher_compiles` fail, or `#[ignore]`, when the cross
   compiler or `qemu-aarch64` is absent. A skip is not a pass.
2. On the provider filter, allow only the thread form of `clone` / `clone3`.
   Add a named test that `clone(SIGCHLD)` is refused. The short filter already
   does this.
3. Prove the seven withheld Landlock rights by allowing `symlinkat` /
   `mknodat` / `linkat` in a test filter and requiring Landlock `EACCES`.
   Do not treat the printed `0x41be` mask as that proof.
4. Add a provider-filter socket falsifier. `F-LC-SOCKET` today only breaks
   the short probe.
5. Stop printing `tests/confine.rs` tables that rename one probe file write
   as `wallet_contract create_managed_account` and the other named ops.
6. On each denied provider row, record the kernel errno and a positive
   control. Keep `journal_corrupt` off the Landlock-read row until that
   errno is in the table.
7. Keep aarch64 and Jetson as NOT RUN until those machines produce their
   own permitted and denied rows. Do not book C9 as proven per platform.
8. If `socketpair(AF_UNIX)` stays, add a row that `socketpair(AF_INET)` is
   refused and name the pair as a C9 departure.
9. Land the escape rows this lab ran (ptrace, `/proc/self/mem`, io_uring,
   bpf, unshare, setns, keyctl, `/dev` nodes, abstract unix) as named tests
   on the provider filter.

## Next

@irzhyran reviews #296 against this report. This PR stays draft.
