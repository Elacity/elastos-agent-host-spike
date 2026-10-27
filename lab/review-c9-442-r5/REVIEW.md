# Adversarial review of PR #442 C9 checker leftovers (round 5)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/c9-r4-fail-closed-9b97` (#442) or
`cursor/linux-confine-e156` (#296).

```text
Lane:         lab/review-c9-442-r5
Branch / PR:  cursor/review-c9-442-r5-a2bc
Reviewed:     Elacity/elastos-agent-host-spike#442
Head:         f19dff97d73de968b588974bbc4657ce5cebdbfb
Checker:      7ad5d7ad7792484c938d075badcfe90937f25bac
Parent:       c7c07e3b5ed970929c5154e21406e47721757889
Prior review: #432 lab/review-c9-296-r4 at c7c07e3b (VERDICT PASS; nine leftovers claimed closed here)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #442 is Claude family)
Date:         27 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The nine r4 leftovers are closed on this head, on the live
`aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)` path
and in the checker when the preboot record is the live four-line form
(`nonce_sha256`, `run_start`, `run_id`, `work=`).

This review ran only from a detached `/tmp` worktree
(`/tmp/review-c9-442-r5-src` at `f19dff97`). Guest init kept the
baked helpers (`worktree_under_tmp=1`). Counts matched the claim:
elf 6/0/0 in 0.48s, aarch64 2/0/1 in 0.04s, confine 25/0/0 in 3.01s,
providers 4/0/0 in 13.57s. Host exit 0. All nine official in-guest
plants CAUGHT. `guest_exit=0` and `qemu_exit=0`. Fail-closed host
exit 1. `LC_QEMU_TIMEOUT=2` smoke: `qemu_exit=137`, host exit 1.

`plants-r4.py` prints 10 CAUGHT / 0 SURVIVED, but several of those
plants still mint the old two-line preboot. Those cases fail on
missing `run_id` / `work=` rather than on the leftover they name.
The unit tests and the complete-fixture plants below are the real
check. Each r4 leftover fails with its named reason when the preboot
is the live format.

The live wrapper always writes `$WORK/host-preboot.txt` as a regular
file, appends `work=` and `run_id=` last after qemu, and mints a new
nonce each boot. Clock skew of +1s still PASSes. The live TCG run
did not false-FAIL on a slow providers suite (13.57s) under the 600s
budget.

Seven new leftover plants SURVIVED the checker API. They do not turn
a failed live boot into HOST_EXIT=0. Exact patches are below.

**VERDICT: PASS** for the emulated-aarch64 C9 claim on this head.

Native aarch64 / Jetson: NOT RUN.
`make-char` / `make-block`: NOT RUN.
`socketpair(AF_UNIX)`: named C9 departure.

C9 cannot be booked without a real ARM board on kernel 6.7+.

## Author claims, rerun

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 52 checker tests (34 original incl. M1–M11, 9 r4 tests, M12–M20) | **HOLDS** | `python3 lab/linux-confine/guest/check-guest-results.test.py -v` → `Ran 52 tests in 2.572s OK`. |
| plants-r4.py 10 CAUGHT / 0 SURVIVED | **HOLDS as a count** | Author script: 10 CAUGHT. R4-2 / R4-8a / R4-9b fail on missing `run_id`/`work=` because that script still writes the old two-line preboot. Complete fixtures close the named leftovers (table below). |
| R4 leftovers closed in the live wrapper path | **HOLDS** | Wrapper mints `$WORK/host-preboot.txt` with `run_id` + `work=`, appends those fields last after qemu, 9p share is `$EVIDENCE` only. |
| live TCG HOST_EXIT=0; elf 6/0/0, aarch64 2/0/1, confine 25/0/0, providers 4/0/0; nine in-guest plants CAUGHT | **HOLDS** | Fresh `/tmp` guest below. |
| fail-closed HOST_EXIT=1 | **HOLDS** | `check_rc=1`, elf SHORT 0/0/0, `guest_exit=1`. |
| `LC_QEMU_TIMEOUT=2` → qemu_exit=137 HOST_EXIT=1 | **HOLDS** | Guest did not print the TCG label. |
| +2s clock skew does not false-FAIL a genuine tree | **HOLDS** | `R5-skew-plus-1s` rc=0. Live TCG providers 13.57s still HOST_EXIT=0. |

## Fresh `/tmp` rerun at f19dff97

Detached worktree only. The PR branch was not checked out and was not pushed.

```text
git worktree add --detach /tmp/review-c9-442-r5-src f19dff97d73de968b588974bbc4657ce5cebdbfb
cd /tmp/review-c9-442-r5-src
LC_GUEST_WORK=/tmp/review-c9-442-r5-work lab/linux-confine/run-aarch64-guest.sh full
# FULL_HOST_EXIT=0
# repo=/tmp/review-c9-442-r5-src
# head=f19dff97d73de968b588974bbc4657ce5cebdbfb
# worktree_under_tmp=1
# qemu=QEMU emulator version 8.2.2
# Guest: Linux 6.18.58-0-virt aarch64, landlock_abi=7
# nonce=c05bf97b41351e5674aa04c355cfab3f
# run_id=b0e25ce87ec7cda9db3f02c8f2e12a44
# work=/tmp/review-c9-442-r5-work
# vmlinuz sha256 d1876369b061ef3bc33314f490240efcd32b031393cb34c6f81134fa862fe472
```

| suite | this `/tmp` rerun | author claim |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.48s | 6 / 0 / 0 |
| aarch64 | 2 / 0 / 1 in 0.04s | 2 / 0 / 1 |
| confine | 25 / 0 / 0 in 3.01s | 25 / 0 / 0 |
| providers | 4 / 0 / 0 in 13.57s | 4 / 0 / 0 |
| F-LC-* in-guest | 9 CAUGHT | 9 CAUGHT |

```text
LC_GUEST_WORK=/tmp/review-c9-442-r5-work lab/linux-confine/run-aarch64-guest.sh fail-closed
# FAIL_CLOSED_HOST_EXIT=1
# elf SHORT 0/0/0
# guest_exit=1
# qemu_exit=0
# check_rc=1

LC_QEMU_TIMEOUT=2 LC_GUEST_WORK=/tmp/review-c9-442-r5-work \
  lab/linux-confine/run-aarch64-guest.sh smoke
# qemu_exit=137
# TIMEOUT_HOST_EXIT=1
# guest did not print the required TCG label
```

## R4 leftovers, complete live-format preboot

Each plant uses `run_id` + `work=` + host-context last-field, the same
record the wrapper writes. 0 = host PASS.

| id | attack | result | evidence |
| --- | --- | --- | --- |
| R4-1b-complete | PREBOOT is a symlink that resolves outside evidence | **CAUGHT** | `pre-boot path is a symlink` |
| R4-1d-complete | PREBOOT path contains `..` | **CAUGHT** | `pre-boot path contains ..` |
| R4-2-complete | same nonce, new `run_id`, fresh mtimes | **CAUGHT** | `nonce was already recorded for this work dir` |
| R4-3-complete | evidence mtimes +1 day | **CAUGHT** | `evidence file mtime is in the future` |
| R4-4a-complete | extra `LC_MARK suite=empty-suite` | **CAUGHT** | `empty-suite: unexpected LC_MARK suite` |
| R4-5a-complete | `guest_exit=0` CRLF | **CAUGHT** | `guest_exit.txt did not report 0` |
| R4-7a-complete | honest confine plus `confine2` FAIL | **CAUGHT** | `confine2: unexpected LC_MARK suite` and unexpected status file |
| R4-8a-complete | PREBOOT from another `$WORK`, same hash/`run_id` | **CAUGHT** | `pre-boot work path does not match host-context` |
| R4-9b-complete | `run_start=0` in a four-line preboot | **CAUGHT** | `pre-boot run_start missing` (regex `[1-9][0-9]*`) |
| R4-live-wrapper-binds-work | wrapper source | **CAUGHT** | mints `$WORK/host-preboot.txt`, appends `work=`/`run_id=` last |

The author's `plants-r4.py` is a weaker report of the same list. It
still writes `nonce_sha256` + `run_start` only. Keep the unit tests
and these complete plants as the falsifiers.

## New plants (r5)

Checker plants used `lab/review-c9-442-r5/plants.py` against the live
`check-guest-results.py` at this head. Control plants (honest tree,
+1s skew, timeout KILL idiom, one allowed `suite=guest` mark) stayed
PASS. That is the false-FAIL check.

| id | attack | result | evidence |
| --- | --- | --- | --- |
| R5-honest-pass | complete live-format fixture | **holds** | rc=0 |
| R5-skew-plus-1s | file mtimes = now+1 | **holds** | rc=0; +2s skew leaves a genuine run green |
| R5-1-nonce-new-work | copy a PASS tree to a new `$WORK`, rewrite `work=` + `run_id` | **SURVIVED** | used-nonces is per work dir. Live wrapper mints a new nonce, so this is checker-API only. |
| R5-1-wipe-used-nonces | unlink `$WORK/used-nonces.txt`, replay | **SURVIVED** | host can delete the ledger. Guest 9p cannot reach `$WORK`. |
| R5-1-fail-then-swap-pass | FAIL tree then swap PASS with the same nonce | **CAUGHT** | preboot-valid trees record the nonce before suite checks |
| R5-2-hardlink-preboot | PREBOOT is a hardlink inside evidence | **CAUGHT** | `pre-boot nonce record is inside the guest-writable evidence dir` |
| R5-2-hardlink-wipe-ledger | hardlink used-nonces into evidence, truncate, replay | **SURVIVED** | host must plant the hardlink. Wiping the old ledger does not pass this live boot (new nonce). |
| R5-3-copied-preboot | copy PREBOOT to another directory | **CAUGHT** | `pre-boot path is not the host-preboot file under the bound work dir` |
| R5-3-bind-mount | PREBOOT via `mount --bind` of `$WORK` | **CAUGHT** | bind path does not equal `$WORK/host-preboot.txt`. Live wrapper never passes a bind path. |
| R5-4-guest-qemu-exit-then-137 | guest writes `qemu_exit=0`, wrapper appends 137 | **CAUGHT** | last `qemu_exit=` wins |
| R5-4-fifo-guest-exit | `guest-exit.txt` is a FIFO | **CAUGHT** | empty read; `guest_exit.txt did not report 0` |
| R5-5-nbsp-suite | extra `suite=confine` + NBSP | **SURVIVED** | line does not match `MARK_LINE`, so it is ignored |
| R5-5-zwsp-elf-mark | standing elf mark name has ZWSP | **CAUGHT** | unexpected name + `elf: missing LC_MARK` |
| R5-5-zwsp-guest-exit | `guest_exit=0` + ZWSP | **CAUGHT** | byte-exact parse refuses it |
| R5-5-double-space-mark | second elf mark with a double space | **SURVIVED** | unparseable extra `LC_MARK` is ignored (not a duplicate) |
| R5-6-run-start-plus-30 | `run_start = now+30` | **CAUGHT** | `pre-boot run_start is implausible` |
| R5-6-run-start-plus-1-aligned | `run_start = now+1` and files touched to now+1 | **SURVIVED** | skew window on `run_start` plus aligned mtimes. Live wrapper writes `int(time.time())` before qemu. |
| R5-7-guest-exit-no-nl | `guest_exit=0` with no trailing LF | **SURVIVED** | `splitlines()` yields one matching line. Honest init writes `echo` + LF. |
| R5-7-partial-status | `elf.status` truncated to `PAS` | **CAUGHT** | status mismatch |
| R5-7-partial-preboot | preboot cut after `nonce_sha256` | **CAUGHT** | `run_start` / `work` / `run_id` missing |
| R5-7-missing-qemu-exit | host-context has no `qemu_exit=` | **CAUGHT** | `qemu_exit missing` |
| R5-8-timeout-kill | `timeout --foreground --signal=KILL` | **holds** | rc=137; wrapper uses this idiom |
| R5-9-extra-mark-{smoke,full,PASS,guest2,helpers} | extra parseable suite names | **CAUGHT** | `unexpected LC_MARK suite` |
| R5-9-dup-guest-mark | two `suite=guest` marks | **CAUGHT** | `duplicate LC_MARK serial line` |
| R5-9-single-guest-mark | one extra allowed `suite=guest` | **holds** | rc=0 on an honest tree |
| R5-10-stale-preboot-other-nonce | new evidence + old `$WORK` preboot | **CAUGHT** | hash / work / run_id mismatch |
| R5-10-stale-copy-after-new-mint | stale preboot copy after a new mint | **CAUGHT** | path and `run_id` mismatch |
| R5-10-restore-stale-bytes | restore old bytes onto `$WORK/host-preboot.txt` | **CAUGHT** | `pre-boot run_id does not match host-context` |
| R5-10-preboot-is-dir | PREBOOT path is a directory | **CAUGHT** | `pre-boot nonce record missing` |

`plants.py` summary: 36 CAUGHT, 7 SURVIVED, 43 plants.

The seven SURVIVED rows are checker-API leftovers. A live boot still
mints a new nonce, writes preboot outside 9p, and copies the console
after qemu. None of those seven rows let this guest turn a short
suite, a KILL timeout, or a replayed old nonce into HOST_EXIT=0.

## Exact patches for survivors

Apply in `lab/linux-confine/guest/check-guest-results.py` unless noted.

### R5-5-nbsp-suite / R5-5-double-space-mark — refuse an unparseable `LC_MARK` line

After `collect_marks`, any console line that contains `LC_MARK` and
does not match `MARK_LINE` is a failure.

```python
def collect_marks(console: str) -> tuple[dict, list[str]]:
    marks = {}
    problems = []
    for match in MARK_LINE.finditer(console):
        name = match.group("suite")
        if name in marks:
            problems.append(f"{name}: duplicate LC_MARK serial line")
        marks[name] = match.groupdict()
    for raw in console.splitlines():
        if "LC_MARK" in raw and MARK_LINE.search(raw) is None:
            problems.append(f"unparseable LC_MARK line: {raw!r}")
    return marks, problems
```

### R5-7-guest-exit-no-nl — require exactly one LF-terminated line

```python
def parse_guest_exit(text: str):
    if "\r" in text or "\0" in text:
        return None
    if not text.endswith("\n") or text.count("\n") != 1:
        return None
    match = GUEST_EXIT_LINE.fullmatch(text[:-1])
    if match is None:
        return None
    return int(match.group(1))
```

### R5-6-run-start-plus-1-aligned — no future `run_start`

Keep the +2s skew on evidence mtimes only.

```python
def run_start_is_implausible(run_start: int, now: int) -> bool:
    return run_start > now
```

### R5-1 / R5-2 ledger wipe — used-nonces stays host-only

The live wrapper already keeps `used-nonces.txt` under `$WORK`,
outside the 9p share. A caller who can unlink or hardlink that file
can also rewrite evidence. Optional hardening:

```python
def used_nonce_path(work_real: pathlib.Path) -> pathlib.Path:
    return work_real / "used-nonces.txt"

def nonce_already_recorded(work_real: pathlib.Path, digest: str) -> str | None:
    used = used_nonce_path(work_real)
    if used.is_symlink() or used.exists() and used.stat().st_nlink > 1:
        return "used-nonces path is a symlink or hardlink"
    # ... existing read ...
```

A copied PASS tree on a new `$WORK` (R5-1-nonce-new-work) still
passes the checker. The wrapper is the replay gate: it mints a new
nonce and a new `run_id` that the guest console must echo. Do not
treat the checker as a replay-proof API without that wrapper.

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
- host fail-closed on a short suite, a duplicate or unexpected mark, a non-canonical `guest_exit`, a non-zero qemu exit, a KILL timeout, a symlink/`..` PREBOOT path, a reused nonce in the same `$WORK`, a future mtime, and a preboot from another `$WORK`

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
- 11 Fail closed: the host wrapper fails a short suite, a non-zero
  qemu exit, and a KILL timeout. The checker now binds PREBOOT to
  this `$WORK` and records a used nonce after a preboot-valid tree.
  The checker still trusts a complete caller-supplied tree on a fresh
  work dir, an unparseable extra `LC_MARK` line, and `guest_exit=0`
  with no trailing LF.
- 12 Docs, code, tests, and operations must agree: keep the label
  `aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.

## Questions

none
