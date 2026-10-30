# Adversarial review of PR #296 C9 aarch64 harness (round 3)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

```text
Lane:         lab/review-c9-296-r3
Branch / PR:  cursor/review-c9-296-r3-ffd6  https://github.com/Elacity/elastos-agent-host-spike/pull/418
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         440354e76c38cb0f30c3509dfd77037d32509263
Parent:       e4003ae0d552030dad13a57834419b44ecf793fe
Prior review: #404 lab/review-296-c9-r2 at 3a90672 (VERDICT PASS; host trusted the guest)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #296 is Claude family)
Date:         26 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The r2 host-wrapper gaps are closed on this head, on the live
`aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)` path.

This review ran only from a detached `/tmp` worktree
(`/tmp/review-c9-296-r3-src` at `440354e76c38`). Guest init kept the
baked helpers (`tmp_mount=tmpfs+baked`). Counts matched the claim:
elf 6/0/0 in 0.46s, aarch64 2/0/1 in 0.04s, confine 25/0/0 in 2.86s,
providers 4/0/0 in 12.79s. Host exit 0. All nine official in-guest
plants CAUGHT, including skip-netns (`netns=host`) with
`dummy0 eth0 lo` present. Standing rows stayed `netns=lo`.
`guest finished status=0` and `guest_exit=0` are the numeric init rc.

The test uid cannot read the nonce. `/etc/lc-nonce` is mode `400`.
`cat` as uid 1000 prints `Permission denied`. `/etc/lc-guest.env` has
no nonce. `evidence/nonce.txt` is absent during the run. The kernel
cmdline is `console=ttyAMA0 earlycon=pl011,0x09000000 panic=1`.
Uid 1000 cannot write `/dev/console`, `/dev/ttyAMA0`, or init's
stdout (`/proc/1/fd/1`). All three are `crw-------` root or
`Permission denied`. A tester process cannot forge `LC_MARK` on the
serial console after init.

The host fails a short suite. Official `fail-closed` ran
`elf --exact no_such_deliberate_fail` (0 passed vs expected 6).
Host exit 1. `guest_exit=1`. A 2s wrapper timeout produced
`qemu_exit=137` and host exit 1. The live KILL path does not write
`qemu_timeout=1` (that line is only for exit 124). The non-zero qemu
exit still fails the host.

Checker unit tests: 28 passed, including r2 mutants M1-M8.

Eight new forgeries of our own, plus live guest probes, are in the
table below. The leftover SURVIVED rows are checker-only: last-wins
duplicate marks, a `guest_exit=0` substring in `guest_exit=01` or in
a later comment, optional `env_has_nonce=0` / `evidence_nonce_during_run=0`
lines, and a replay of a complete old evidence tree when the caller
also supplies that old nonce. The live wrapper mints a new nonce and
wipes the evidence dir. Uid 1000 cannot write the serial, so last-wins
is not a live forge. Honest init writes one `guest_exit=$guest_rc`
line. Those leftovers do not reopen the r2 holes on this boot.

**VERDICT: PASS** for the emulated-aarch64 C9 claim on this head.
Keep native aarch64 / Jetson as NOT RUN. Keep `make-char` /
`make-block` as NOT PROVEN. Keep `socketpair(AF_UNIX)` as the named
C9 departure. C9 cannot be booked without a real ARM board on
kernel 6.7+.

## Author claims, rerun

| Claim | Verdict | Evidence |
| --- | --- | --- |
| nonce in `/etc/lc-nonce` mode 0400, unreadable by tester uid 1000 | **HOLDS** | Live: `nonce_file_mode=400`, `cat: can't open '/etc/lc-nonce': Permission denied`, `tester_nonce_readable=0`, `REVIEW_tester_nonce_file=0`. Wrapper writes the file after qemu exits. |
| `LC_MARK` required and must match 9p counts exactly | **HOLDS** | Missing marks fail (`test_forged_9p_only_missing_marks_fails`). Inflation with matching marks fails (`passed 7 != expected 6`). Live marks matched 6/2/25/4. |
| non-zero qemu exit fails | **HOLDS** | `qemu_exit=137` fixture and live 2s KILL both fail the host. |
| 600s timeout fails | **HOLDS** on exit code | Wrapper uses `timeout --foreground --signal=KILL`. Live `LC_QEMU_TIMEOUT=2` → `qemu_exit=137`, `TIMEOUT_HOST_EXIT=1`. The `qemu_timeout=1` line is only written for exit 124, so it is absent on the live KILL path. The host still exits 1. |
| qemu stdin `/dev/null` | **HOLDS** | Script has `< /dev/null`. Full boot finished `qemu_exit=0` with no tty. |
| 28 checker tests | **HOLDS** | `python3 lab/linux-confine/guest/check-guest-results.test.py -v` → `Ran 28 tests in 0.770s OK`. |
| r2 mutants M1-M8 rejected | **HOLDS** | `MutantsAreCaught` eight tests: live checker rc=1, mutant copy rc=0. |
| 9 official plants CAUGHT | **HOLDS** | CAPBND, BLOCK, STORAGE, PROVIDER-SOCKET, SOCKET, ANY-ERRNO, SKIP-NETNS (`netns=host`), DROP-SECCOMP, WIDE-ROOT. Host-only plants stay `NOT_RUN`. |
| `guest_exit` is the numeric init rc | **HOLDS** on the honest path | Init writes `guest_exit=$guest_rc`. Live: `--- guest finished status=0 ---`, `guest_exit=0`, `LC_MARK suite=guest exit=0`. Fail-closed: `guest_exit=1`, `suite=guest exit=1`. Substring leftovers: N8, N9. |

## Fresh `/tmp` rerun at 440354e

Detached worktree only. The PR branch was not checked out and was not pushed.

```text
git worktree add --detach /tmp/review-c9-296-r3-src 440354e76c38cb0f30c3509dfd77037d32509263
cd /tmp/review-c9-296-r3-src
# local-only review probes added to guest/init.sh (not pushed to #296)
LC_GUEST_WORK=/tmp/review-c9-296-r3-work lab/linux-confine/run-aarch64-guest.sh full
# HOST_EXIT=0
# repo=/tmp/review-c9-296-r3-src
# head=440354e76c38cb0f30c3509dfd77037d32509263
# worktree_under_tmp=1
# tmp_mount=tmpfs+baked
# guest_nics=dummy0 eth0 lo
# helpers_visible=/tmp/review-c9-296-r3-src/target-build/.../out
# qemu=QEMU emulator version 8.2.2
# Guest: Linux 6.18.58-0-virt aarch64, landlock_abi=7, uid=1000
# nonce=7b87f87505a09f934e4edb4c536b8bf4
# vmlinuz sha256 d1876369b061ef3bc33314f490240efcd32b031393cb34c6f81134fa862fe472
```

| suite | this `/tmp` rerun | committed RESULTS (author `/tmp/lc-wt-c9-r2`) |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.46s | 6 / 0 / 0 in 0.61s |
| aarch64 | 2 / 0 / 1 in 0.04s | 2 / 0 / 1 in 0.05s |
| confine | 25 / 0 / 0 in 2.86s | 25 / 0 / 0 in 3.38s |
| providers | 4 / 0 / 0 in 12.79s | 4 / 0 / 0 in 13.91s |
| F-LC-* in-guest | 9 CAUGHT | 9 CAUGHT |

The ignored aarch64 row is still `aarch64_qemu_user_host_kernel`.
That is a qemu-user / host-kernel row. It is not this TCG guest and
not a board.

```text
LC_GUEST_WORK=/tmp/review-c9-296-r3-work lab/linux-confine/run-aarch64-guest.sh fail-closed
# FAIL_CLOSED_HOST_EXIT=1
# elf: test result: ok. 0 passed; 0 failed; 0 ignored; 6 filtered out
# status=SHORT exit=0
# guest_exit=1
# LC_MARK suite=guest exit=1
# nonce=2b022bbc73bd61733fc9db2b111a51e7

LC_QEMU_TIMEOUT=2 LC_GUEST_WORK=/tmp/review-c9-296-r3-work \
  lab/linux-confine/run-aarch64-guest.sh smoke
# qemu_exit=137
# TIMEOUT_HOST_EXIT=1
# qemu_timeout=1 was not written (live KILL path)
```

## New mutants and forgeries (not M1-M8)

Live guest probes ran as uid 1000 inside the same full boot. Checker
forgeries used a copy of `check-guest-results.py` fixtures. 0 = host PASS.

| id | attack | result | evidence |
| --- | --- | --- | --- |
| N-console | tester writes `LC_MARK` to `/dev/console` | **CAUGHT** | `crw------- root root`; `sh: can't create /dev/console: Permission denied`; `REVIEW_console_w=0` `REVIEW_console_echo=0` |
| N-ttyAMA0 | tester writes to `/dev/ttyAMA0` | **CAUGHT** | `crw------- root root`; `Permission denied`; `REVIEW_ttyAMA0_w=0` `REVIEW_ttyAMA0_echo=0` |
| N-init-stdout | tester writes to `/proc/1/fd/1` | **CAUGHT** | `sh: can't create /proc/1/fd/1: Permission denied`; `REVIEW_init_stdout_w=0` |
| N-replay-old | replay committed 9p+serial+old nonce into the checker | **SURVIVED** | First run, complete committed tree, nonce `eacadb6e...`, checker rc=0. The wrapper mints a new nonce each boot, so this is not a live wrapper bypass. |
| N-replay-new | same old files, fresh host nonce | **CAUGHT** | `serial nonce eacadb6e... != ffff...` |
| N-cmdline | nonce on kernel cmdline or tester `/proc/cmdline` | **CAUGHT** | cmdline is `console=ttyAMA0 earlycon=pl011,0x09000000 panic=1`; `REVIEW_cmdline_has_nonce=0` |
| N-proc-environ | nonce in `/proc/1/environ` readable by uid 1000 | **CAUGHT** | `REVIEW_tester_proc1_environ_r=0`; init unsets `LC_GUEST_NONCE` |
| N-9p-env | nonce in `/etc/lc-guest.env` or 9p `nonce.txt` before qemu exits | **CAUGHT** | `env_has_nonce=0` `evidence_nonce_during_run=0` `REVIEW_tester_env_nonce=0` `REVIEW_tester_9p_nonce=0` |
| N4 | suite reports extra passes, marks match | **CAUGHT** | `elf: passed 7 != expected 6` |
| N1b / N5 | duplicate `LC_MARK` lines, last matches 9p | **SURVIVED** | Checker is last-wins. Live tester cannot write the serial, so a late forge is not available on this guest. |
| N-timeout | timeout path leaves `HOST_EXIT=0` | **CAUGHT** | Live wrapper `LC_QEMU_TIMEOUT=2` → `qemu_exit=137` `TIMEOUT_HOST_EXIT=1`. Fixture `qemu_timeout=1` with `qemu_exit=0` still fails the checker. |
| N8 | `guest_exit=1` plus a later `guest_exit=0` comment | **SURVIVED** | `"guest_exit=0" in file` is a substring check. Honest init truncates to one `guest_exit=$guest_rc` line. |
| N9 | `guest_exit=01` | **SURVIVED** | Same substring. Shell `$?` does not write a leading zero. `guest_exit=10` is CAUGHT (N7). |
| N1c | late forged mark and inflated 9p together | **CAUGHT** | Exact expected counts still fire. |

A guest that already writes matching 9p files can still write
`guest_exit=0`. That is the same 9p trust as r2. This head adds a
serial mark that the test uid cannot forge, a root-only nonce the
test uid cannot read, and a qemu-exit / timeout fail-closed.

## What in C9 can count on this emulated aarch64

This head is a real aarch64 Linux kernel (Alpine virt 6.18.58,
Landlock ABI 7) on an emulated CPU. These C9 rows are that kernel's:

- aarch64 ELF for the lab binaries and the three provider debug binaries
- aarch64 Landlock syscall numbers 444 / 445 / 446, ABI 7, including `IOCTL_DEV`
- user namespace + empty caps + `CapBnd` 0 + `no_new_privs`
- mount / ipc / pid namespaces, and a net namespace that stays `lo` while the guest itself has `dummy0` and `eth0`
- seccomp allow-list refusals on this aarch64 syscall ABI
- fail-closed start when Landlock, seccomp, or user namespaces are blocked
- the nine in-guest plants, including skip-netns once a second NIC exists
- host fail-closed on a short suite, a missing mark, a non-zero qemu exit, and a KILL timeout

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
C9 cannot be booked without a real ARM board on kernel 6.7+.

## Not run here

- native aarch64 / Jetson: **NOT RUN**
- `make-char` / `make-block` unconfined success: **NOT RUN** (no `CAP_MKNOD`)
- `socketpair(AF_UNIX)`: named C9 departure, not closed

## Principles

- 3 No ambient authority: the guest rows still deny outside read/write,
  socket, unbound exec, and host signal when the launcher is intact.
- 5 Small trusted core: this review is lab evidence only.
- 11 Fail closed: the host wrapper now fails a short suite, a missing
  `LC_MARK`, a non-zero qemu exit, and a KILL timeout. The nonce stays
  off the test uid. The checker still trusts guest-written 9p files.
- 12 Docs, code, tests, and operations must agree: keep the label
  `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.

## Questions

none
