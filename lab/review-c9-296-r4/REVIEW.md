# Adversarial review of PR #296 C9 aarch64 harness (round 4)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/linux-confine-e156`.

```text
Lane:         lab/review-c9-296-r4
Branch / PR:  cursor/review-c9-296-r4-c477  https://github.com/Elacity/elastos-agent-host-spike/pull/432
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         c7c07e3b5ed970929c5154e21406e47721757889
Parent:       05a7195b6e21b0b1edda0b49bd00730fac5de5da
Prior review: #418 lab/review-c9-296-r3 at 440354e (VERDICT PASS; three leftovers claimed closed here)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #296 is Claude family)
Date:         27 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The three r3 leftovers are closed on this head, on the live
`aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)` path.

This review ran only from a detached `/tmp` worktree
(`/tmp/review-c9-296-r4-src` at `c7c07e3b`). Guest init kept the
baked helpers (`tmp_mount=tmpfs+baked`). Counts matched the claim:
elf 6/0/0 in 0.50s, aarch64 2/0/1 in 0.05s, confine 25/0/0 in 3.65s,
providers 4/0/0 in 15.29s. Host exit 0. All nine official in-guest
plants CAUGHT, including skip-netns (`netns=host`) with
`dummy0 eth0 lo` present. Standing rows stayed `netns=lo`.
`guest finished status=0` and `guest_exit=0` are the numeric init rc.

Duplicate `LC_MARK` fails closed. `guest_exit=01` and other non-canonical
exit files fail. A replayed tree with old mtimes fails against a new
`run_start`. The host writes `$WORK/host-preboot.txt` (sha256 of the
nonce plus `run_start`) before qemu. That file is outside the 9p share.
The live guest could not overwrite it.

Checker unit tests: 34 passed, including r2 mutants M1-M8 and r3
mutants M9-M11.

Nine new plants of our own are in the table below. Several SURVIVED
as checker-API leftovers: a symlink or `..` PREBOOT path that resolves
outside evidence, a reused nonce with fresh mtimes, a future mtime,
an extra unknown `LC_MARK`, CRLF in `guest_exit.txt`, a colliding
`confine2` name, a matching preboot from another `$WORK`, and
`run_start=0`. The live wrapper mints a new nonce each boot and
passes its own `$WORK/host-preboot.txt`. The guest 9p share is only
`$EVIDENCE`. Those leftovers do not let this guest turn a failed
boot into HOST_EXIT=0.

**VERDICT: PASS** for the emulated-aarch64 C9 claim on this head.

Native aarch64 / Jetson: NOT RUN.
`make-char` / `make-block`: NOT RUN.
`socketpair(AF_UNIX)`: named C9 departure.

C9 cannot be booked without a real ARM board on kernel 6.7+.

## Author claims, rerun

| Claim | Verdict | Evidence |
| --- | --- | --- |
| duplicate `LC_MARK` fails closed | **HOLDS** | `test_duplicate_lc_mark_last_wins_fails`; plant R3-dup-lc-mark rc=1 (`elf: duplicate LC_MARK serial line`). M9 mutant copy rc=0. |
| `guest_exit.txt` is exactly one canonical line | **HOLDS** on the stated regex | `guest_exit=01`, two lines, and a comment all fail. Trailing NUL fails. CRLF is accepted by `splitlines()` (R4-5a). Honest init writes `guest_exit=$guest_rc\n`. |
| host mints nonce pre-boot; sha256 + `run_start` in `$WORK/host-preboot.txt` outside 9p | **HOLDS** | File written before qemu. Live hash `9a2ef20f…` matches nonce `f25f7a4d…`. 9p share is `$EVIDENCE` with `mapped-xattr`. Guest abs write of `/tmp/linux-confine-aarch64/host-preboot.txt` failed. WORK file mtime stayed at mint time. |
| mismatched nonce / missing preboot / preboot inside evidence / old mtimes fail | **HOLDS** | R3-replay-old-mtime, R4-1a, R4-1c, R4-8b, missing-PREBOOT argv. |
| 34 checker tests; M1-M11 killed | **HOLDS** | `python3 lab/linux-confine/guest/check-guest-results.test.py -v` → `Ran 34 tests in 1.175s OK`. |
| live boot elf 6/0, aarch64 2/0/1, confine 25/0, providers 4/0 | **HOLDS** | Full guest below. Host x86_64 cargo after building the three provider binaries: elf 6, aarch64 2/0/1, confine 25, providers 4. |
| all 9 official in-guest plants CAUGHT | **HOLDS** | CAPBND, BLOCK, STORAGE, PROVIDER-SOCKET, SOCKET, ANY-ERRNO, SKIP-NETNS (`netns=host`), DROP-SECCOMP, WIDE-ROOT. |

## Fresh `/tmp` rerun at c7c07e3b

Detached worktree only. The PR branch was not checked out and was not pushed.

```text
git worktree add --detach /tmp/review-c9-296-r4-src c7c07e3b5ed970929c5154e21406e47721757889
cd /tmp/review-c9-296-r4-src
# local-only review probes added to guest/init.sh (not pushed to #296)
LC_GUEST_WORK=/tmp/review-c9-296-r4-work lab/linux-confine/run-aarch64-guest.sh full
# FULL_HOST_EXIT=0
# repo=/tmp/review-c9-296-r4-src
# head=c7c07e3b5ed970929c5154e21406e47721757889
# worktree_under_tmp=1
# tmp_mount=tmpfs+baked
# guest_nics=dummy0 eth0 lo
# helpers_visible=/tmp/review-c9-296-r4-src/target-build/.../out
# qemu=QEMU emulator version 8.2.2
# Guest: Linux 6.18.58-0-virt aarch64, landlock_abi=7, uid=1000
# nonce=f25f7a4dabeefdc5b9cda513c019fd89
# vmlinuz sha256 d1876369b061ef3bc33314f490240efcd32b031393cb34c6f81134fa862fe472
# nonce_file_mode=400 tester_nonce_readable=0 env_has_nonce=0 evidence_nonce_during_run=0
# CapBnd=0000000000000000 ioctl_dev_ready=yes
```

| suite | this `/tmp` rerun | author claim |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.50s | 6 / 0 / 0 in 0.50s |
| aarch64 | 2 / 0 / 1 in 0.05s | 2 / 0 / 1 in 0.04s |
| confine | 25 / 0 / 0 in 3.65s | 25 / 0 / 0 in 2.95s |
| providers | 4 / 0 / 0 in 15.29s | 4 / 0 / 0 in 12.54s |
| F-LC-* in-guest | 9 CAUGHT | 9 CAUGHT |

The ignored aarch64 row is still `aarch64_qemu_user_host_kernel`.
That is a qemu-user / host-kernel row. It is not this TCG guest and
not a board.

```text
LC_GUEST_WORK=/tmp/review-c9-296-r4-work lab/linux-confine/run-aarch64-guest.sh fail-closed
# FAIL_CLOSED_HOST_EXIT=1
# elf: test result: ok. 0 passed; 0 failed; 0 ignored; 6 filtered out
# status=SHORT exit=0
# guest_exit=1
# LC_MARK suite=guest exit=1
# nonce=a410ec99e9d2c00af72606110ffa0482

LC_QEMU_TIMEOUT=2 LC_GUEST_WORK=/tmp/review-c9-296-r4-work \
  lab/linux-confine/run-aarch64-guest.sh smoke
# qemu_exit=137
# TIMEOUT_HOST_EXIT=1
# qemu_timeout=1 was not written (live KILL path)
# guest did not print the required TCG label → wrapper exit 1
```

## New plants (not M1-M11)

Checker plants used `lab/review-c9-296-r4/plants.py` against the live
`check-guest-results.py` at this head. 0 = host PASS. Live 9p probes
ran as root in the same full boot (local `init.sh` only).

| id | attack | result | evidence |
| --- | --- | --- | --- |
| R3-dup-lc-mark | duplicate `LC_MARK`, last matches 9p | **CAUGHT** | `elf: duplicate LC_MARK serial line` |
| R3-guest-exit-01 | `guest_exit=01` | **CAUGHT** | `guest_exit.txt did not report 0: 'guest_exit=01'` |
| R3-replay-old-mtime | old tree + matching nonce + mtimes before `run_start` | **CAUGHT** | every evidence file `predates the run start` |
| R4-1a | PREBOOT is a regular file inside evidence | **CAUGHT** | `pre-boot nonce record is inside the guest-writable evidence dir` |
| R4-1b | PREBOOT is a symlink in evidence that resolves outside | **SURVIVED** | checker `resolve()` follows the link; rc=0. Live wrapper does not pass this path. |
| R4-1c | `$WORK/host-preboot.txt` is a symlink into evidence | **CAUGHT** | `resolve()` lands inside evidence |
| R4-1d | PREBOOT is `evidence/../work/host-preboot.txt` | **SURVIVED** | `resolve()` is outside evidence; rc=0. Live wrapper passes `$WORK/host-preboot.txt`. |
| R4-1 live | guest writes host-preboot via 9p `../` or symlink | **CAUGHT** | `/evidence/../host-preboot.txt` is guest `/host-preboot.txt` (initramfs), not host `$WORK`. Abs write of `/tmp/linux-confine-aarch64/host-preboot.txt` failed. 9p `ln -s` stored the target path as a 43-byte file in evidence; write-through failed (`nonexistent directory`). Host `$WORK/host-preboot.txt` hash and mtime unchanged. |
| R4-2 | same nonce, new preboot `run_start`, `touch` all files | **SURVIVED** | checker rc=0. Live wrapper mints a new nonce each boot. |
| R4-3 | evidence mtimes one day in the future | **SURVIVED** | checker only rejects `mtime < run_start`. Live guest `touch -t 203001010000` on 9p set mtime `1893456000`. |
| R4-4a | extra `LC_MARK suite=empty-suite passed=0` | **SURVIVED** | unknown suite names are ignored |
| R4-4b | standing `elf` reports 0 tests | **CAUGHT** | `elf: passed 0 != expected 6` |
| R4-5a | `guest_exit=0` CRLF | **SURVIVED** | `splitlines()` strips `\r`; line matches the regex |
| R4-5b | `guest_exit=0` + trailing NUL | **CAUGHT** | `guest_exit.txt did not report 0: 'guest_exit=0\x00'` |
| R4-5c | `guest_exit=0\n` then NUL | **CAUGHT** | two logical lines |
| R4-6a | qemu 137 + complete PASS tree | **CAUGHT** | `qemu_exit=137 is non-zero/abnormal` |
| R4-6b | qemu killed before `qemu_exit=` is written | **CAUGHT** | `qemu_exit missing from host-context.txt` |
| R4-6 live | `LC_QEMU_TIMEOUT=2` KILL mid-boot | **CAUGHT** | `qemu_exit=137`, `TIMEOUT_HOST_EXIT=1` |
| R4-7a | honest `confine` plus failing `confine2` | **SURVIVED** | extra colliding name is ignored |
| R4-7b | only `suite=confine2` mark | **CAUGHT** | `confine: missing LC_MARK serial line` |
| R4-8a | checker PREBOOT from another `$WORK`, same hash | **SURVIVED** | checker binds the hash, not the minting path |
| R4-8b | other `$WORK`, other nonce hash | **CAUGHT** | `nonce does not match the pre-boot record` |
| R4-9a | `run_start` 30s after file mtimes (guest behind) | **CAUGHT** | fail-closed: files `predates the run start` |
| R4-9b | `run_start=0` | **SURVIVED** | regex allows 0; age check never fires |
| R4-9 live | host vs guest clock | clocks matched | guest `2026-10-27T00:33:53+00:00`; `run_start=1793061133`; guest date `1793061233` (100s later, the build). No skew. |

`plants.py` summary: 14 CAUGHT, 9 SURVIVED, 23 plants.

## Exact patches for survivors

These are checker-only leftovers. They do not change the live wrapper
path on this boot. Apply in `lab/linux-confine/guest/check-guest-results.py`.

### R4-1b / R4-1d — refuse a PREBOOT path that starts in evidence or contains `..`

In `collect_preboot_problems`, before `resolve()`:

```python
    if ".." in preboot.parts:
        problems.append("pre-boot path contains ..")
        return problems
    try:
        preboot.absolute().relative_to(evidence_real)
        problems.append("pre-boot nonce record is inside the guest-writable evidence dir")
        return problems
    except ValueError:
        pass
    if preboot.is_symlink():
        try:
            preboot.parent.resolve().relative_to(evidence_real)
            problems.append("pre-boot nonce record is a symlink from the guest-writable evidence dir")
            return problems
        except ValueError:
            pass
```

Keep the existing `preboot.resolve().relative_to(evidence_real)` check
after this (that is R4-1c).

### R4-2 — a reused nonce with fresh mtimes

The checker is stateless. Same nonce + matching hash + `touch` is a
second successful check, not a second boot. The live wrapper mints a
new nonce, so this is not a live guest bypass.

To bind one boot, write a host-only `run_id` into preboot and append
the same `run_id` to `host-context.txt` after qemu returns. Then:

```python
# after reading preboot
# run_id = ... from preboot
# host_run_id = ... last run_id= line in host-context.txt (host appends last)
# if run_id != host_run_id: problems.append("pre-boot run_id does not match host-context")
```

Do not treat nonce + mtime as a unique run.

### R4-3 — reject a future mtime

```python
        now = int(time.time())
        mtime = int(child.stat().st_mtime)
        if mtime < run_start:
            problems.append(f"{child.name}: evidence file predates the run start")
        elif mtime > now + 2:
            problems.append(f"{child.name}: evidence file mtime is in the future")
```

### R4-4a / R4-7a — refuse an unexpected `LC_MARK` suite

After `collect_marks`, with `expected` in scope (pass it in):

```python
    allowed = set(expected["suites"]) | {"guest"}
    allowed |= set(expected.get("plants_caught", []))
    allowed |= set(expected.get("plants_not_run", []))
    for name in marks:
        if name not in allowed:
            problems.append(f"{name}: unexpected LC_MARK suite")
```

### R4-5a — refuse CRLF

```python
def parse_guest_exit(text: str):
    if "\r" in text or "\0" in text:
        return None
    lines = text.splitlines()
    if len(lines) != 1:
        return None
    match = GUEST_EXIT_LINE.fullmatch(lines[0])
    if match is None:
        return None
    return int(match.group(1))
```

### R4-8a — bind PREBOOT to the minting path

Write `work=<absolute $WORK>` into preboot. Require
`preboot.resolve() == Path(work).resolve() / "host-preboot.txt"`.
A copied file in another directory then fails.

### R4-9b — refuse `run_start=0`

```python
PREBOOT_START_LINE = re.compile(r"^run_start=([1-9][0-9]*)$")
```

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
- host fail-closed on a short suite, a duplicate mark, a non-canonical `guest_exit`, a non-zero qemu exit, a KILL timeout, and a preboot / nonce / old-mtime mismatch

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
- host `F-LC-QEMU-USER-LANDLOCK`: **NOT RUN** (`qemu-aarch64` absent). `F-LC-WRONG-ARCH-CC` was CAUGHT on the host check.

## Principles

- 3 No ambient authority: the guest rows still deny outside read/write,
  socket, unbound exec, and host signal when the launcher is intact.
- 5 Small trusted core: this review is lab evidence only.
- 11 Fail closed: the host wrapper fails a short suite, a duplicate
  `LC_MARK`, a non-canonical `guest_exit`, a non-zero qemu exit, and a
  KILL timeout. The nonce stays off the test uid. The checker still
  trusts a caller-supplied preboot path and a complete guest-written
  tree whose mtimes are fresh.
- 12 Docs, code, tests, and operations must agree: keep the label
  `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.

## Questions

none
