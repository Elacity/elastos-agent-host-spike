# Adversarial review of PR #296 C9 fixes (r3)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`.

```text
Lane:         lab/review-c9-296-r3
Branch / PR:  cursor/review-c9-296-r3-2982  https://github.com/Elacity/elastos-agent-host-spike/pull/361
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         9a769ad109164c8e40b080d63144d8138141baf0
Parent:       121f9c4cac91a125d9810f819ddecfedb792795c
Tree:         /tmp/wt/linux-confine-296-r3 (detached, fetched origin/cursor/linux-confine-e156)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64 exec: NOT RUN
Jetson:       NOT RUN
```

C9 wording used here is the same as draft PRs #326 and #349: namespaces,
capabilities, seccomp and Landlock, with permitted and denied rows per
platform. B4 is the permission-model table.

## Plain summary

The three WEAK items from draft PR #349 are fixed on this head, on this
x86_64 kernel.

Denied rows now carry an exact errno. Swapping clone `EPERM` for `EACCES`
fails the standing test. The author's `F-LC-ANY-ERRNO` plant is still
CAUGHT. A review plant that treats `EPERM` and `EACCES` as the same deny
does survive, so the standing check is exact, not "any permission error".

`ioctl-dev` is a real device ioctl. Confined it is Landlock `EACCES` on
the bind-mounted `/dev/urandom`. Unconfined `RNDGETENTCNT` succeeds
(entropy count 256). `ioctl(0)` on `/dev/urandom` is `EINVAL` 22; the
same call on `/dev/null` is `ENOTTY` 25. Dropping the bind-mount, using
ioctl request 0, or falling back on every error, each fails the standing
test. `make-char` / `make-block` stay confined Landlock `EACCES` and
unconfined `EPERM`. The author marks those two as NOT PROVEN.

`build.rs` uses `aarch64-linux-gnu-gcc` for a foreign TARGET. Default
`cargo check --target aarch64-unknown-linux-gnu` exits 101 and says
host `cc` is not used. `CC=cc` is ignored. Setting `TARGET_CC=cc` or
`CC_aarch64_unknown_linux_gnu=cc` still compiles the C helpers with
host `cc` and `cargo check` finishes. Those binaries are x86-64 ELF
under the aarch64 output dir. That is the leftover honesty gap if those
variables point at the host compiler. Real aarch64 execution is NOT RUN.

When Landlock reports absent, the 18 launch tests fail closed with
`the kernel has no Landlock`. The 7 tests that still pass are parse
tests, the production-launcher switch test, and the absence / ABI
explain hooks. No confinement row can pass without Landlock.

`socketpair(AF_UNIX)` still succeeds on the provider filter and still
carries bytes inside the process. `socket`, `bind`, `connect`,
`sendmsg`, and `socketpair(AF_INET)` stay refused. That pair is a named
C9 / B4 departure. It is an open decision for Anders.

**C9 is bookable on this x86_64 Linux host apart from aarch64/Jetson and
the mknod controls.** Keep aarch64 and Jetson as NOT RUN until those
machines produce their own rows. Keep `make-char` / `make-block` as NOT
PROVEN until a machine with `CAP_MKNOD` produces an unconfined success.
Give Anders the Unix pair.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| confine 25, providers 4, falsify 6/6, clippy clean | **HOLDS** | Confine `25 passed; 0 failed; 0 ignored`. Providers `4 passed; 0 failed; 0 ignored`. `F-LC-SOCKET`, `F-LC-CAPBND`, `F-LC-BLOCK`, `F-LC-STORAGE`, `F-LC-PROVIDER-SOCKET`, `F-LC-ANY-ERRNO` each printed `CAUGHT`. Clippy exit 0. |
| Exact errno on every denied `expect()` row; `F-LC-ANY-ERRNO` CAUGHT | **HOLDS** | Standing `expect()` asserts errno twice on a refused row. `provider_filter_refuses_clone_process` also asserts `EPERM`. `F-LC-ANY-ERRNO` printed `CAUGHT`. Review plant `M-R3-SWAP-ERRNO` (clone deny returns `EACCES`) failed with `left: Some(13)` / `right: Some(1)`. |
| `EPERM` vs `EACCES` treated as the same deny | **WEAK** as a nearby check; standing code still HOLDS | `M-R3-EITHER-ERRNO` loosened both errno asserts to accept 1 or 13, then returned `EACCES` for clone. `provider_filter_refuses_clone_process` passed. `F-LC-ANY-ERRNO` plants `ENOSYS` (38), so it does not cover a 1↔13 swap. The standing asserts still require the exact number. |
| `ioctl-dev` is `RNDGETENTCNT` on bind-mounted `/dev/urandom` | **HOLDS** | Confined withheld test: `ioctl-dev` refused errno 13, reason `landlock refused IOCTL_DEV`. Unconfined shipped probe: `ioctl-dev` ok, `ioctl RNDGETENTCNT succeeded`. Host: `/dev/urandom` `RNDGETENTCNT` ok value=256; `/dev/urandom` ioctl 0 errno 22; `/dev/null` ioctl 0 and `RNDGETENTCNT` errno 25. |
| `make-char` / `make-block` NOT PROVEN as positive controls | **HOLDS** | Confined errno 13, reason Landlock `MAKE_CHAR` / `MAKE_BLOCK`. Unconfined errno 1 (`EPERM`). Test prints the NOT PROVEN line and does not ask for unconfined success. |
| aarch64 skip is ignored, never a pass | **HOLDS** | Default: `0 passed; 0 failed; 1 ignored`. `--ignored` panicked: `This ignored test must not count as a pass.` |
| `build.rs` honours `CC_<target>` / `TARGET_CC`; aarch64 is NOT RUN | **HOLDS** on the default path; **WEAK** if those vars name host `cc` | Default and `CC=cc`: exit 101, `cannot run aarch64-linux-gnu-gcc`, `Host cc is not used`. `TARGET_CC=cc` and `CC_aarch64_unknown_linux_gnu=cc`: exit 0. `file` on that `lc-setup` is `ELF 64-bit LSB pie executable, x86-64`. Empty `CC_<target>` / `TARGET_CC` fail closed again. Real aarch64 execution is NOT RUN. |
| Low Landlock ABI cannot skip `IOCTL_DEV` | **HOLDS** | `M-R3-ABI-EXPLAIN` removed the ABI `< 5` refusal; `explain_abi(4)` returned `abi-ok` and `a_low_landlock_abi_refuses_the_start` failed. `M-R3-ABI-SKIP-IOCTL` also dropped `IOCTL_DEV` from the handled mask; confined `ioctl-dev` was `ok` and the withheld test failed (`left: "ok"` / `right: "refused"`). |
| A confinement test can pass when Landlock is unavailable | **HOLDS** that launch proofs fail closed | `M-R3-NO-LANDLOCK` made `landlock_abi()` return -1. Suite: `7 passed; 18 failed`. The 18 launch tests failed with `the kernel has no Landlock`. The 7 passes are `profiles_match_their_declared_rights`, `unknown_allow_is_refused`, `a_wider_root_read_is_refused`, `production_launcher_rejects_block_switches`, `landlock_absence_refuses_the_start`, `seccomp_absence_refuses_the_start`, `a_low_landlock_abi_refuses_the_start`. |
| `socketpair(AF_UNIX)` stays; named C9 departure | open decision for Anders | Provider filter: pair `ok`, pair I/O `ok`. `connect` / `bind` / `sendmsg` errno 1. `socketpair(AF_INET/INET6/NETLINK)` errno 1. `socket(AF_UNIX)` errno 1. |

## Claimed suite, this session

Worktree `9a769ad1`. Provider debug binaries were built first.

```text
uname -srm
# Linux 6.12.94+ x86_64

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
# exit 101
# cannot run aarch64-linux-gnu-gcc for TARGET=aarch64-unknown-linux-gnu: No such file or directory (os error 2).
# Set CC_aarch64_unknown_linux_gnu. Host cc is not used for a foreign target. Real aarch64 execution is NOT RUN.

python3 lab/linux-confine/falsify.py
# F-LC-SOCKET CAUGHT
# F-LC-CAPBND CAUGHT
# F-LC-BLOCK CAUGHT
# F-LC-STORAGE CAUGHT
# F-LC-PROVIDER-SOCKET CAUGHT
# F-LC-ANY-ERRNO CAUGHT
# exit 0

cargo clippy --manifest-path lab/linux-confine/Cargo.toml --all-targets -- -D warnings
# Finished `dev` profile ... in 2.02s
# exit 0
```

`aarch64-linux-gnu-gcc` and `qemu-aarch64` are absent on this VM.

## ioctl-dev and withheld rights

`withheld_storage_rights_are_landlock_eacces` passed. Confined probe
rows this session:

```text
make-sym / make-fifo / make-sock / make-char / make-block / ioctl-dev  errno 13
refer  errno 18
refer-mkdir  ok
```

Unconfined shipped `lc-probe`:

```text
op=make-sym result=ok
op=make-fifo result=ok
op=make-sock result=ok
op=make-char result=refused errno=1
op=make-block result=refused errno=1
op=refer result=ok
op=ioctl-dev result=ok reason=ioctl RNDGETENTCNT succeeded
```

Host ioctl on this uid:

```text
host urandom-rnd ok value=256
host urandom-zero refused errno=22
host null-zero refused errno=25
host null-rnd refused errno=25
```

The unconfined probe has no launcher bind-mount, so it opens
`/dev/urandom` through the documented leftover-file fallback. That is
the same `RNDGETENTCNT` call the confined path makes on the bind-mounted
node. Request 0 is not a success on either device.

## Extra process and socketpair probe

`probe.c` is freestanding. It was launched through a standing `lc-setup`
from `9a769ad1`. The unconfined extra probe stops after
`clone3-thread`: that child shares the thread group and calls
`exit_group`. The provider-filter run is complete because `clone3` is
`ENOSYS` there.

Provider filter:

```text
enforced abi=6 uid=0 caps=empty nnp=1 netns=lo storage_rights=0x41be
op=clone-sigchld result=refused errno=1
op=clone-vm-sigchld result=refused errno=1
op=clone-vfork result=refused errno=1
op=clone-thread result=ok
op=fork result=refused errno=1
op=vfork result=refused errno=1
op=clone3-sigchld result=refused errno=38
op=clone3-thread result=refused errno=38
op=socketpair-unix result=ok
op=socketpair-unix-io result=ok
op=socketpair-connect result=refused errno=1
op=socketpair-bind result=refused errno=1
op=socketpair-sendmsg result=refused errno=1
op=socketpair-inet result=refused errno=1
op=socketpair-inet6 result=refused errno=1
op=socketpair-netlink result=refused errno=1
op=socket-unix result=refused errno=1
op=socket-inet result=refused errno=1
```

Anders owns whether that Unix pair is the Linux mapping.

## Provider denied rows

| Provider | Denied row | errno this session | Positive control printed |
| --- | --- | --- | --- |
| did | write / read outside | 13 | unconfined read of the outside file |
| did / wallet / model | socket | 1 | unconfined `socket(AF_INET)` |
| did / wallet / model | exec a copy | 13 | unconfined exec of the copy |
| did / wallet / model | signal host pid | 3 | unconfined `kill(host, 0)` |
| wallet | write / read outside | 13 | unconfined read of the outside file |
| model | write / read outside | 13 | unconfined read of the outside file |

Model print: `provider mapping for the denied outside journal read stays journal_corrupt: model run journal is unavailable. That string is not the Landlock-read row.`

CapBnd on the three binaries was `0000000000000000`.

Those provider tests exec `capsules/<name>/target/debug/<name>` from this
tree. Installed release binaries, aarch64 provider binaries, and Jetson
binaries were NOT RUN.

## Mutants (worktree only, restored)

`python3 -I lab/review-c9-296-r3/mutants.py` edited the fetched tree, ran
the named test, then wrote the original file back.
`git -C /tmp/wt/linux-confine-296-r3 status --short` was empty. `HEAD`
stayed `9a769ad1`.

| Plant | What changed | Named test | Result |
| --- | --- | --- | --- |
| `M-R3-SWAP-ERRNO` | Process-clone denial returns `EACCES` instead of `EPERM` | `provider_filter_refuses_clone_process` | **CAUGHT**. `left: Some(13)` / `right: Some(1)`. |
| `M-R3-EITHER-ERRNO` | `expect()` and the extra clone assert accept 1 or 13; clone deny returns `EACCES` | `provider_filter_refuses_clone_process` | **SURVIVED**. `1 passed`. |
| `M-R3-IOCTL-ZERO` | `RNDGETENTCNT` becomes `0` | `withheld_storage_rights_are_landlock_eacces` | **CAUGHT**. Unconfined `ioctl-dev` refused errno 22. |
| `M-R3-NO-BIND` | Skip the `/dev/urandom` bind-mount | `withheld_storage_rights_are_landlock_eacces` | **CAUGHT**. Reason became `open of planted device failed`. |
| `M-R3-IOCTL-FALLBACK-ANY` | Fall back to `/dev/urandom` on every ioctl error | `withheld_storage_rights_are_landlock_eacces` | **CAUGHT**. Same wrong reason. |
| `M-R3-ABI-SKIP-IOCTL` | Drop the ABI `< 5` refusal and drop `IOCTL_DEV` from the handled mask | `withheld_storage_rights_are_landlock_eacces` | **CAUGHT**. `ioctl-dev` `ok`. |
| `M-R3-ABI-EXPLAIN` | Drop only the ABI `< 5` refusal | `a_low_landlock_abi_refuses_the_start` | **CAUGHT**. `explain_abi(4)` returned `abi-ok`. |
| `M-R3-NO-LANDLOCK` | `landlock_abi()` always returns -1 | full `--test confine` | **18 launch tests failed**. 7 non-launch tests passed. |

`python3 -I lab/review-c9-296-r3/build_env.py` did not edit the tree.

| Env | `cargo check --target aarch64-unknown-linux-gnu` | Result |
| --- | --- | --- |
| cleared `CC` / `TARGET_CC` | exit 101 | host `cc` is not used |
| `CC=cc` | exit 101 | host `CC` is ignored |
| `TARGET_CC=cc` | exit 0 | host `cc` compiled x86-64 `lc-setup` |
| `CC_aarch64_unknown_linux_gnu=cc` | exit 0 | same x86-64 helpers |
| empty `CC_<target>` and `TARGET_CC` | exit 101 | falls through to `aarch64-linux-gnu-gcc` |

## What remains NOT RUN

- Jetson execution
- Real aarch64 execution (`qemu-aarch64` and `aarch64-linux-gnu-gcc` are absent)
- Cross-compile of `setup.c` / `probe.c` / `witness.c` with an aarch64 compiler
- Installed / release provider binaries
- A live x32 ABI socket
- Unconfined `make-char` / `make-block` success (`CAP_MKNOD` is absent)

## Bookability

Anders's rule: a check counts only when its complete journey, refusal
evidence, and required reviews all pass.

C9 asks for those four layers with permitted and denied rows per
platform. This VM produced the x86_64 Linux rows, including the three
fixes from #349. aarch64 and Jetson still have no executed rows.
`make-char` / `make-block` still have no unconfined success.
`socketpair(AF_UNIX)` is a named departure for Anders.

**C9 is bookable on this x86_64 Linux host apart from aarch64/Jetson and
the mknod controls.** Keep those two as NOT RUN / NOT PROVEN. Give
Anders the Unix pair.

## Next

#296 stays draft. This PR stays draft. Do not merge either.
