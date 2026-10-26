# Adversarial review of PR #296 fail-closed aarch64 runner (round 2)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

```text
Lane:         lab/review-296-c9-r2
Branch / PR:  cursor/review-296-c9-r2-f54b
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         3a90672f509a7b75465b8d0d53019dbf3eb36102
Parent:       0ab7b013fdc4f1d564a8982b4c5b42456f1ca2a0
Prior review: #393 at de819640 (VERDICT PASS, with four host-wrapper gaps)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #296 is Claude family)
Date:         26 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The four gaps from review #393 are closed on this head.

The host now reads per-suite `.exit` / `.status` and rust `test result:`
lines from the 9p share, plus `LC_MARK` serial lines that carry a nonce.
A short suite, a missing suite, or a missing plant makes the host exit 1.
The official `fail-closed` mode ran `elf --exact no_such_deliberate_fail`
(0 passed against an expected 6). Host exit was 1.

A `/tmp` worktree works. This review ran only from a detached checkout at
`/tmp/review-296-3a90672`. Guest init moved the baked `/tmp` tree aside,
mounted tmpfs, and bind-mounted the helpers back
(`tmp_mount=tmpfs+baked`, `helpers_visible=.../tmp/review-296-3a90672/...`).
Counts matched the author's claim.

The guest has `dummy0 eth0 lo`. Standing rows still print `netns=lo`.
The skip-netns plant printed `netns=host` and was CAUGHT. Drop-seccomp
and wide-root were CAUGHT on the same boot.

The unbound-exec wait now matches the whole line
`linux confinement refused: exec of PROVIDER_EXECUTABLE (<copy>) failed errno=13`.
The three provider logs on this boot contain that exact line.

`RESULTS.txt` on this rerun was written by `check-guest-results.py` from
the live guest files. The nonce and the suite times differ from the
committed copy.

The label stayed
`aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.
`native=0`, `jetson=0`, `emulated_cpu=1`, `qemu_accel=tcg`. Kernel dmesg
mentions a CPU feature string that includes the word KVM. That is the
guest kernel text. The qemu command used `-accel tcg`.

The host verdict trusts the guest. The nonce is in `/etc/lc-guest.env`,
`/etc/lc-nonce`, and `evidence/nonce.txt`. Init and `run-c9.sh` write the
`LC_MARK` lines. The rust test process can read those files. Missing
`LC_MARK` lines are accepted when the 9p files look complete. A guest
that writes matching 9p files can make the host exit 0. The wrapper
catches an incomplete or short honest run. It does not authenticate the
guest.

**VERDICT: PASS** for the emulated-aarch64 C9 claim on this head. Keep
native aarch64 / Jetson as NOT RUN. Keep `make-char` / `make-block` as
NOT PROVEN. Keep `socketpair(AF_UNIX)` as the named C9 departure.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| elf 6/0/0, aarch64 2/0/1, confine 25/0/0, providers 4/0/0 | **HOLDS** from `/tmp` | Live rust last lines: elf `6 passed; 0 failed; 0 ignored` in 0.52s; aarch64 `2 passed; 0 failed; 1 ignored` in 0.04s; confine `25 passed; 0 failed; 0 ignored` in 3.22s; providers `4 passed; 0 failed; 0 ignored` in 13.84s. Host exit 0. |
| Nine official in-guest plants CAUGHT, including skip-netns | **HOLDS** | Live plant logs: CAPBND (`CapBnd` did not drop), BLOCK (production launcher accepted `--block-landlock`), STORAGE (rights drifted), PROVIDER-SOCKET / SOCKET (`op=socket result=ok`), ANY-ERRNO (`not any failure`), SKIP-NETNS (`netns=host`), DROP-SECCOMP (`op=socket result=ok`), WIDE-ROOT (`op=outside-read result=ok`). Host-only plants stay `NOT_RUN`. |
| `/tmp` worktree keeps helpers after guest tmpfs | **HOLDS** | `repo=/tmp/review-296-3a90672`, `worktree_under_tmp=1`, `tmp_mount=tmpfs+baked`, helpers executable at the baked path. Same counts as the author's `/workspace` claim. |
| Host fail-closes on a short or missing suite | **HOLDS** | `run-aarch64-guest.sh fail-closed` → rust `0 passed; 0 failed; 0 ignored; 6 filtered out`, status SHORT, host `HOST_EXIT=1`. Checker listed `passed 0 < expected 6` and the three missing suites. Rust itself exited 0; the host still failed. |
| Exact unbound-exec line, not any `errno=13` | **HOLDS** | `unbound_exec_reason` waits for the whole line with this copy path. Live `providers.txt` has that line for did, wallet, and model. |
| `RESULTS.txt` comes from live guest files | **HOLDS** | Fresh file starts `# GENERATED from this guest run` with nonce `4aeaf5d26eda4264778fa98a165fa3ee`. Times differ from the committed copy (0.52 / 0.04 / 3.22 / 13.84 vs 0.51 / 0.04 / 2.78 / 12.54). |
| Label is emulated CPU, never native ARM or Jetson | **HOLDS** | `LABEL.txt`, guest console, and abi-probe all print the TCG label. `uname.machine=aarch64`, `uname.release=6.18.58-0-virt`. `jetson=1` is absent. qemu 8.2.2 `-accel tcg`. |
| Guest kernel is a real aarch64 Linux, ABI 7 | **HOLDS** | `Booting Linux on physical CPU 0x0000000000`, `Linux version 6.18.58-0-virt`, `landlock_create_ruleset nr=444 ret=7`, `landlock_abi=7`, `ioctl-dev` Landlock EACCES on did/wallet/model. vmlinuz sha256 `d1876369...` matches the committed stamp. |
| Binaries under test are aarch64 ELF from this head | **HOLDS** | `e_machine=183` on guest-bins, `lc-setup*`, `lc-probe`, `lc-witness.so`, and the three provider debug binaries. |
| Suites ran as guest uid 1000; printed `uid=0` is user-ns | **HOLDS** | `run-c9.sh` printed `uid=1000 gid=1000`. `enforced abi=7 uid=0` is the launcher's user-namespace map, same as #393. |
| Host verdict is independent of a guest that writes 9p / serial | **WEAK** | Nonce is guest-readable. `LC_MARK` is optional. qemu exit code is unused. A guest that writes matching 9p files gets host exit 0. See attacks below. This is a completeness check, not a guest-authentication check. |
| Author unit tests pin the host checker | **WEAK** | Three tests: happy path, short elf, missing plant. Six of eight mutants change a property those tests never touch. |
| This proves C9 on real ARM hardware | **does not hold** | TCG emulated CPU. Alpine virt kernel. Debug gnu binaries. No board, no Jetson, no `CAP_MKNOD`. |

## Fresh `/tmp` rerun at 3a90672

Detached worktree only. The PR branch was not checked out and was not pushed.

```text
git worktree add --detach /tmp/review-296-3a90672 3a90672f509a7b75465b8d0d53019dbf3eb36102
cd /tmp/review-296-3a90672
LC_GUEST_WORK=/tmp/review-296-c9-work lab/linux-confine/run-aarch64-guest.sh full
# HOST_EXIT=0
# repo=/tmp/review-296-3a90672
# head=3a90672f509a7b75465b8d0d53019dbf3eb36102
# worktree_under_tmp=1
# tmp_mount=tmpfs+baked
# guest_nics=dummy0 eth0 lo
# helpers_visible=/tmp/review-296-3a90672/target-build/.../out
# qemu=QEMU emulator version 8.2.2
# Guest: Linux 6.18.58-0-virt aarch64, landlock_abi=7, uid=1000
# nonce=4aeaf5d26eda4264778fa98a165fa3ee
```

| suite | this `/tmp` rerun | committed RESULTS (parent boot) |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.52s | 6 / 0 / 0 in 0.51s |
| aarch64 | 2 / 0 / 1 in 0.04s | 2 / 0 / 1 in 0.04s |
| confine | 25 / 0 / 0 in 3.22s | 25 / 0 / 0 in 2.78s |
| providers | 4 / 0 / 0 in 13.84s | 4 / 0 / 0 in 12.54s |
| F-LC-* in-guest | 9 CAUGHT | 9 CAUGHT |

The ignored aarch64 row is still `aarch64_qemu_user_host_kernel` (needs
`qemu-aarch64` inside the guest). That is a qemu-user / host-kernel row.
It is not this TCG guest and not a board.

Standing `enforced` lines:
`abi=7 uid=0 caps=empty nnp=1 netns=lo storage_rights=0x41be`.
Did-provider `CapBnd` is `0000000000000000`.

```text
LC_GUEST_WORK=/tmp/review-296-c9-work lab/linux-confine/run-aarch64-guest.sh fail-closed
# HOST_EXIT=1
# elf: test result: ok. 0 passed; 0 failed; 0 ignored; 6 filtered out
# status=SHORT exit=0
# guest_exit=1
# nonce=9312f33aeb321e12e637ed3a22f69bf1
```

## Host verdict attacks

The nonce is a stale-file token. It is not a secret from the guest.

- Host creates it with `secrets.token_hex(16)` and writes `evidence/nonce.txt` on the 9p share before boot.
- The same value is in initramfs `/etc/lc-guest.env` and `/etc/lc-nonce` (mode 644).
- `init.sh` (PID 1) and `run-c9.sh` (tester uid 1000) source that env and print `LC_MARK`.
- `run-c9.sh` does not export the vars (`set -eu` only), so the rust test process does not inherit `LC_GUEST_NONCE` as an environment variable.
- The test process can still read `/etc/lc-guest.env`, `/etc/lc-nonce`, or `/evidence/nonce.txt`.

`LC_MARK` lines are written by the guest scripts, not by the host. The
checker treats a missing mark as "skip the serial cross-check". A
present mark must match the 9p counts and the host nonce.

`qemu_exit` is recorded in `host-context.txt` and then ignored. There is
no qemu timeout.

Checker fixtures (original `check-guest-results.py`, 0 = host PASS):

| id | setup | host | meaning |
| --- | --- | --- | --- |
| A0 | honest complete files | 0 | control |
| A1 | short elf (5 passed) | 1 | short suite fails |
| A2 | missing skip-netns plant | 1 | missing plant fails |
| A3 | 9p complete, no `LC_MARK` | 0 | truncated serial is accepted |
| A4 | guest writes matching 9p + marks with the known nonce | 0 | guest can satisfy the host |
| A5 | last rust line inflated; serial still honest | 1 | serial cross-check fires when marks exist |
| A6 | last rust line inflated; no marks | 0 | passed is a floor; extra passed is accepted |
| A7 | inflated last line and matching mark | 0 | guest that forges both sides passes |
| A8 | two elf marks, same values | 0 | last-wins, consistent |
| A9 | second elf mark disagrees | 1 | last-wins, conflict fails |
| A10 | `guest_exit=1` | 1 | guest fail is a host fail |
| A11 | missing `guest-exit.txt` | 1 | panic before that file fails |
| A12 | providers files missing | 1 | timeout mid-run fails |
| A13 | host nonce absent from guest files | 1 | stale or swapped evidence fails |
| A14 | elf status FAIL exit 1 | 1 | honest fail fails |
| A15 | `qemu_exit=137` in host-context, 9p complete | 0 | checker never reads qemu_exit |
| A16 | serial truncated; nonce only in 9p | 0 | 9p nonce is enough |
| A17 | later printed `test result: ok. 6 passed` after a fail line | 0 | last-line wins |
| A18 | zero-test elf SHORT | 1 | 0 passed vs expected 6 fails |

A rust harness writes its own `test result:` line last, so an ordinary
test `println` does not inflate the count. A rewriter or a later 9p
write can. The fail-closed probe is the honest zero-test case, and the
host caught it.

## Host-checker mutants (8)

Each mutant is a one-site edit of a copy of `check-guest-results.py`.
The author's three unit tests always load the original file, so they
cannot see these copies. The table is our fixtures against each mutant
(0 = that checker exited 0).

| mutant | honest | short_elf | miss_plant | guest_exit_1 | wrong_nonce | missing_providers | status_fail | extra probe |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| original | 0 | 1 | 1 | 1 | 1 | 1 | 1 | — |
| M1 skip plant CAUGHT | 0 | 1 | **0** | 1 | 1 | 1 | 1 | missing plant survives |
| M2 skip passed floor | 0 | **0** | 1 | 1 | 1 | 1 | 1 | short suite survives |
| M3 skip status/exit | 0 | 1 | 1 | 1 | 1 | 1 | **0** | FAIL+exit 1 survives |
| M4 skip nonce presence | 0 | 1 | 1 | 1 | 1 | 1 | 1 | no-marks + wrong nonce: orig 1, mutant **0** |
| M5 skip guest_exit | 0 | 1 | 1 | **0** | 1 | 1 | 1 | guest_exit=1 survives |
| M6 first result line | 0 | 1 | 1 | 1 | 1 | 1 | 1 | first-ok last-fail: orig 1, mutant **0** |
| M7 skip failed-exact | 0 | 1 | 1 | 1 | 1 | 1 | 1 | failed=1: orig 1, mutant **0** |
| M8 missing status = PASS | 0 | 1 | 1 | 1 | 1 | 1 | 1 | unlink elf.status: orig 1, mutant **0** |

The live checker still has those checks. Removing any of the eight lets
a bad fixture through. The author's unit tests only pin M1-shaped and
M2-shaped holes (missing plant, short suite). The other six properties
are real in the script and untested in-tree.

## What in C9 can count on this emulated aarch64

This head is a real aarch64 Linux kernel (Alpine virt 6.18.58, Landlock
ABI 7) on an emulated CPU. These C9 rows are that kernel's:

- aarch64 ELF (`e_machine=183`) for the lab binaries and the three provider debug binaries
- aarch64 Landlock syscall numbers 444 / 445 / 446, ABI 7, including `IOCTL_DEV`
- `ioctl-dev` Landlock `EACCES` on did, wallet, and model
- user namespace + empty caps + `CapBnd` 0 + `no_new_privs`
- mount / ipc / pid namespaces, and a net namespace that stays `lo` while the guest itself has `dummy0` and `eth0`
- seccomp allow-list refusals on this aarch64 syscall ABI
- fail-closed start when Landlock, seccomp, or user namespaces are blocked
- withheld storage rights (`make-sym` / `make-fifo` / `make-sock` / `refer` / `ioctl-dev`) as Landlock `EACCES` / `EXDEV`
- exact unbound `execve` of a storage-root copy, errno 13, with the copy path on the line
- the nine in-guest plants, including skip-netns once a second NIC exists

The named C9 departure stays: `socketpair(AF_UNIX)` is allowed for the
Tokio thread; `socket` and `socketpair(AF_INET)` stay refused.

## What still needs real ARM hardware (kernel ABI >= 5)

A Jetson or other aarch64 board, that board's kernel (6.7 or newer so
Landlock ABI is at least 5), and the binaries that board actually ships:

- that board's kernel, modules, cmdline, and Landlock ABI number
- musl versus gnu, `ldd` paths, loader cache, and CPU features on that board
- KVM or native execution instead of TCG
- `make-char` / `make-block` as positive controls (`CAP_MKNOD`)
- any board-specific seccomp or Landlock quirk

TCG is a real aarch64 kernel on an emulated CPU. It is not that board.

## Principles

- 3 No ambient authority: the guest rows still deny outside read/write,
  socket, unbound exec, and host signal when the launcher is intact.
- 5 Small trusted core: this review is lab evidence only.
- 11 Fail closed: Landlock / seccomp / userns absence still refuse the
  start. The host wrapper now fails closed on a short or missing honest
  suite. The wrapper still trusts guest-written 9p files.
- 12 Docs, code, tests, and operations must agree: keep the label
  `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.

## Questions

none
