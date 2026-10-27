# Adversarial review of PR #442 C9 checker leftovers (round 6)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`
and does not push `cursor/c9-r4-fail-closed-9b97` (#442) or
`cursor/linux-confine-e156` (#296).

```text
Lane:         lab/review-c9-442-r6
Branch / PR:  cursor/review-c9-442-r6-a6bd  https://github.com/Elacity/elastos-agent-host-spike/pull/473
Reviewed:     Elacity/elastos-agent-host-spike#442
Head:         862f4c881313163c8071286c8172806436d8e1ca
Checker:      4396d77ee5afc84d1cc60b03e1327471fe3f43a1
Parent:       f19dff97d73de968b588974bbc4657ce5cebdbfb
Prior review: #454 lab/review-c9-442-r5 at f19dff97 (VERDICT PASS; seven leftovers claimed closed here)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, qemu-system-aarch64 8.2.2, aarch64-linux-gnu-gcc 13.3.0
Reviewer:     Cursor Grok 4.6 (Grok / xAI family; author of #442 is Claude family)
Date:         27 Oct 2026
Aarch64 exec: qemu-system-aarch64 TCG, Alpine virt 6.18.58-0-virt, Landlock ABI 7
Native ARM:   NOT RUN
Jetson:       NOT RUN
```

## Plain English

The named r5 leftovers are closed when the checker sees one pinned
`LC_USED_NONCES` file. `plants-r4.py` now writes the live four-line
preboot. The unit file has 65 tests. The author's `plants.py` is
43 CAUGHT / 0 SURVIVED.

This review ran the live guest from a detached `/tmp` worktree
(`/tmp/review-c9-442-r6-src` at `862f4c88`). Guest init kept the
baked helpers (`worktree_under_tmp=1`). Counts matched the claim:
elf 6/0/0 in 0.46s, aarch64 2/0/1 in 0.03s, confine 25/0/0 in 2.80s,
providers 4/0/0 in 12.37s. Host exit 0. All nine official in-guest
plants CAUGHT. `guest_exit=0` and `qemu_exit=0`. Fail-closed host
exit 1 (`guest_exit=1`, elf SHORT 0/0/0). `LC_QEMU_TIMEOUT=2` smoke:
`qemu_exit=137`, host exit 1, no TCG label.

The live wrapper still does not pin `LC_USED_NONCES`. The default
ledger follows `XDG_RUNTIME_DIR` or `/var/tmp` and is a
read-modify-write of one text file, with no flock and no `O_APPEND`.
A fresh XDG, an unlink of that file, a crash that empties it, or a
parent directory that is a symlink into 9p evidence, lets the same
nonce PASS again.

The timeout path is worse. `run-aarch64-guest.sh` exits 1 on a
missing LABEL before it runs the checker, so the minted nonce is
never recorded. This review took the live timeout nonce
`8b7627491634646ff11c6d0bbbf07de3` and the live
`$WORK/host-preboot.txt`, built a forged PASS tree, and ran the
checker against the real host ledger. Checker rc=0.

That is a false PASS after a real failed live boot. The wrapper
itself stayed exit 1 on that boot. The leftover is the unused
nonce.

**VERDICT: FIX**

Native aarch64 / Jetson: NOT RUN.
`make-char` / `make-block`: NOT RUN (RESULTS: no `CAP_MKNOD`).
`socketpair(AF_UNIX)`: named C9 departure.

C9 cannot be booked without a real ARM board on kernel 6.7+.

## Author claims, rerun

| Claim | Verdict | Evidence |
| --- | --- | --- |
| r5 leftovers closed: host-side ledger outside `$WORK` and 9p | **HOLDS for `$WORK` wipe / new `$WORK`** | Pinned `LC_USED_NONCES`: `R6-r5-1-nonce-new-work-pinned` and `R6-r5-1-wipe-work-used-nonces` rc=1, `nonce was already recorded for this host boot`. |
| nlink>1 refused on ledger and preboot | **HOLDS** | Author `R5-2-hardlink-*` CAUGHT. `test_r5_2_hardlink_wipe_ledger_fails` and M24/M25. |
| byte-exact ASCII `LC_MARK` | **HOLDS** | Author `R5-5-nbsp-suite` / `R5-5-double-space-mark` CAUGHT. |
| `run_start` not in the future | **HOLDS** | Author `R5-6-run-start-plus-1-aligned` CAUGHT. +1s file skew still PASSes. |
| `guest_exit` ends in exactly one LF | **HOLDS** | Author `R5-7-guest-exit-no-nl` CAUGHT. |
| `plants-r4.py` writes the four-line preboot | **HOLDS** | `write_live_preboot` writes `nonce_sha256`, `run_start`, `run_id`, `work=`. 10 CAUGHT / 0 SURVIVED. |
| checker has 65 tests | **HOLDS** | `python3 lab/linux-confine/guest/check-guest-results.test.py -v` → `Ran 65 tests in 2.499s OK`. |
| `plants.py` 43/43 CAUGHT | **HOLDS** | `summary: 43 CAUGHT, 0 SURVIVED, 43 plants`. |
| live TCG HOST_EXIT=0 | **HOLDS** | Fresh `/tmp` guest below. |
| fail-closed HOST_EXIT=1 | **HOLDS** | `check_rc=1`, elf SHORT 0/0/0, `guest_exit=1`. |
| timeout 137 | **HOLDS** | `qemu_exit=137`, host exit 1, no TCG label. |

## Fresh `/tmp` rerun at 862f4c88

Detached worktree only. The PR branch was not pushed.

```text
git worktree add --detach /tmp/review-c9-442-r6-src 862f4c881313163c8071286c8172806436d8e1ca
cd /tmp/review-c9-442-r6-src
LC_GUEST_WORK=/tmp/review-c9-442-r6-work lab/linux-confine/run-aarch64-guest.sh full
# FULL_HOST_EXIT=0
# repo=/tmp/review-c9-442-r6-src
# head=862f4c881313163c8071286c8172806436d8e1ca
# worktree_under_tmp=1
# qemu=QEMU emulator version 8.2.2
# nonce=91f098f9d6c88356717b9def20054abc
# run_id=037a80bd5c71dce3d1538f642fd1a8c6
# work=/tmp/review-c9-442-r6-work
# vmlinuz sha256 d1876369b061ef3bc33314f490240efcd32b031393cb34c6f81134fa862fe472
```

| suite | this `/tmp` rerun | author claim |
| --- | --- | --- |
| elf | 6 / 0 / 0 in 0.46s | 6 / 0 / 0 |
| aarch64 | 2 / 0 / 1 in 0.03s | 2 / 0 / 1 |
| confine | 25 / 0 / 0 in 2.80s | 25 / 0 / 0 |
| providers | 4 / 0 / 0 in 12.37s | 4 / 0 / 0 |
| F-LC-* in-guest | 9 CAUGHT | 9 CAUGHT |

```text
LC_GUEST_WORK=/tmp/review-c9-442-r6-work lab/linux-confine/run-aarch64-guest.sh fail-closed
# FAIL_CLOSED_HOST_EXIT=1
# elf SHORT 0/0/0
# guest_exit=1
# qemu_exit=0
# check_rc=1

LC_QEMU_TIMEOUT=2 LC_GUEST_WORK=/tmp/review-c9-442-r6-work \
  lab/linux-confine/run-aarch64-guest.sh smoke
# qemu_exit=137
# TIMEOUT_HOST_EXIT=1
# guest did not print the required TCG label
# nonce=8b7627491634646ff11c6d0bbbf07de3  (never recorded)
```

## R5 leftovers, complete live-format preboot

0 = host PASS. Author `plants.py` and this review's pinned-ledger
re-plants.

| id | attack | result | evidence |
| --- | --- | --- | --- |
| R5-honest-pass | complete live-format fixture | **holds** | rc=0 |
| R5-skew-plus-1s | file mtimes = now+1 | **holds** | rc=0 |
| R4-1b-complete | PREBOOT symlink | **CAUGHT** | `pre-boot path is a symlink` |
| R4-1d-complete | PREBOOT contains `..` | **CAUGHT** | `pre-boot path contains ..` |
| R4-2-complete | same nonce, new `run_id` | **CAUGHT** | `nonce was already recorded for this host boot` |
| R4-3-complete | evidence mtimes +1 day | **CAUGHT** | `evidence file mtime is in the future` |
| R4-4a-complete | extra `suite=empty-suite` | **CAUGHT** | `unexpected LC_MARK suite` |
| R4-5a-complete | `guest_exit=0` CRLF | **CAUGHT** | `guest_exit.txt did not report 0` |
| R4-7a-complete | extra `confine2` FAIL | **CAUGHT** | unexpected mark and status file |
| R4-8a-complete | other `$WORK`, same hash/`run_id` | **CAUGHT** | `pre-boot work path does not match host-context` |
| R4-9b-complete | `run_start=0` | **CAUGHT** | `pre-boot run_start missing` |
| R5-1-nonce-new-work | new `$WORK`, pinned ledger | **CAUGHT** | host-boot ledger |
| R5-1-wipe-used-nonces | unlink `$WORK/used-nonces.txt` | **CAUGHT** | host-boot ledger; `$WORK` file is unused |
| R5-2-hardlink-wipe-ledger | hardlink ledger, truncate | **CAUGHT** | `used-nonces path is a symlink or hardlink` |
| R5-5-nbsp-suite / double-space | unparseable `LC_MARK` | **CAUGHT** | `unparseable LC_MARK line` |
| R5-6-run-start-plus-1-aligned | `run_start = now+1` | **CAUGHT** | `pre-boot run_start is implausible` |
| R5-7-guest-exit-no-nl | no trailing LF | **CAUGHT** | `guest_exit.txt did not report 0` |

`plants-r4.py` summary: 10 CAUGHT, 0 SURVIVED, 10 plants.

## New plants (r6)

Checker plants used `lab/review-c9-442-r6/plants.py` against the live
`check-guest-results.py` at this head. False-FAIL / hang controls
(honest tree, missing ledger on a first run, leftover lock file)
stayed PASS and did not hang. A leftover symlink at the ledger path
false-FAILs an honest tree (fail-closed). A clock step-back that
makes `run_start > now` also false-FAILs.

| id | attack | result | evidence |
| --- | --- | --- | --- |
| R6-honest-pass | complete live-format fixture | **holds** | rc=0 |
| R6-missing-ledger-first-run | `LC_USED_NONCES` path does not exist | **holds** | rc=0; first run creates the file |
| R6-missing-xdg-ledger-first-run | empty `XDG_RUNTIME_DIR` | **holds** | rc=0 |
| R6-stale-lock-no-hang | leftover `used-nonces.lock` | **holds** | rc=0 in 0.024s; there is no flock |
| R6-fresh-xdg-resets-ledger | same nonce after new `XDG_RUNTIME_DIR` | **SURVIVED** | default path is `XDG/linux-confine/used-nonces-<boot>.txt` |
| R6-fresh-home-same-xdg | new `HOME`, same XDG | **CAUGHT** | `HOME` does not select the ledger |
| R6-delete-host-ledger | unlink the host ledger file | **SURVIVED** | next check treats it as a first run |
| R6-ledger-inside-evidence | `LC_USED_NONCES` under 9p, unlink | **SURVIVED** | guest uid can wipe it |
| R6-world-writable-ledger-wipe | pre-create 0666, truncate after | **SURVIVED** | checker `chmod 0600` then a later chmod+truncate PASSes |
| R6-symlinked-ledger-dir | `XDG/linux-confine` → evidence | **SURVIVED** | `path_is_alias` checks the file, not the parent |
| R6-parallel-same-nonce | two concurrent checks | **CAUGHT this run** | rc=(0,1); one lost the race. No lock, so this can flip. |
| R6-partial-ledger-write | truncate ledger to 17 bytes | **SURVIVED** | `ledger_digests` does not see the full digest |
| R6-empty-ledger-after-crash | empty the file after a PASS | **SURVIVED** | `write_text` truncates first |
| R6-rmw-lost-update | replay a digest lost by RMW | **SURVIVED** | record is read-modify-write, not `O_APPEND` |
| R6-ledger-not-oappend-locked | source | **holds** | `write_text`; no `flock` / `O_APPEND` |
| R6-clock-run-start-one-hour-past | `run_start = now-3600` | **holds** | rc=0 |
| R6-clock-step-back-false-fail | `run_start = now+30` | **CAUGHT** | models a backwards clock; honest run would false-FAIL |
| R6-preboot-rename-toctou | rename a hardlink over PREBOOT | **CAUGHT this run** | `nlink_after=2` and rc=1. Window remains: nlink and `read_text` are two opens. |
| R6-serial-forged-guest-exit | `guest-exit.txt` is 1; console says 0 | **CAUGHT** | file wins |
| R6-qemu137-rewrite-same-ledger | rewrite 137→0, same ledger | **CAUGHT** | preboot-valid trees record the nonce even when qemu is 137 |
| R6-qemu137-rewrite-fresh-xdg | rewrite 137→0, new XDG | **SURVIVED** | same hole as fresh XDG |
| R6-timeout-skip-then-forged-pass | unused nonce + PASS tree | **SURVIVED** | first checker call PASSes |
| R6-wrapper-timeout-skips-checker | source | **holds** | missing LABEL exits before the checker |
| R6-wrapper-does-not-pin-ledger | source | **holds** | wrapper never sets `LC_USED_NONCES` |
| R6-stale-symlink-ledger-false-fail | dangling symlink ledger | **CAUGHT** | honest tree false-FAILs |
| R6-alias-ignores-parent-dir | source | **holds** | parent symlink is not checked |
| LIVE-timeout-nonce-forged-pass-default-ledger | live timeout nonce + forged PASS on the real host ledger | **SURVIVED** | digest `fc5fea2e…` was absent; checker rc=0 |
| LIVE-fail-closed-nonce-fresh-xdg-pass | fail-closed nonce + new XDG + PASS tree | **SURVIVED** | XDG reset |

`plants.py` (r6) summary: 18 CAUGHT, 10 SURVIVED, 28 plants.

The ten SURVIVED rows are leftover ways to get checker rc=0 after a
failed or replayed boot. The live timeout nonce on the real host
ledger is the one that is not only a fixture.

## Exact patches for survivors

Apply in `lab/linux-confine/guest/check-guest-results.py` and
`lab/linux-confine/run-aarch64-guest.sh`.

### 1. Record the nonce before qemu, on every exit path

`run-aarch64-guest.sh` today mints `$WORK/host-preboot.txt` then
exits 1 on a missing LABEL without calling the checker. Record the
digest in the same step that writes the preboot.

```bash
# after RUN_ID=... host-preboot write
BOOT_ID="$(tr -d '-' < /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
export LC_USED_NONCES="/var/tmp/linux-confine/used-nonces-${BOOT_ID}.txt"
mkdir -m 700 -p /var/tmp/linux-confine
python3 - "$LC_USED_NONCES" "$NONCE" "$RUN_ID" "$BOOT_ID" <<'PY'
import fcntl, hashlib, os, sys
path, nonce, run_id, boot = sys.argv[1:]
digest = hashlib.sha256(nonce.encode()).hexdigest()
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
data = os.read(fd, 1 << 20).decode()
if digest not in {ln.split()[0] for ln in data.splitlines() if ln}:
    os.write(fd, f"{digest} {run_id} {boot}\n".encode())
    os.fsync(fd)
os.close(fd)
os.chmod(path, 0o600)
print(path)
PY
```

Use this same path for the later checker call. Do not honour a
caller `XDG_RUNTIME_DIR` on the live wrapper.

This closes LIVE-timeout-nonce-forged-pass and
R6-wrapper-timeout-skips-checker.

### 2. Pin the checker ledger; ignore XDG for the live path

```python
def used_nonce_path(work_real: pathlib.Path) -> pathlib.Path:
    override = os.environ.get("LC_USED_NONCES")
    if override:
        return pathlib.Path(override)
    return pathlib.Path("/var/tmp") / "linux-confine" / f"used-nonces-{host_boot_id()}.txt"
```

The live wrapper must export `LC_USED_NONCES` (patch 1). Tests keep
using the override. This closes R6-fresh-xdg-resets-ledger and
R6-qemu137-rewrite-fresh-xdg.

### 3. Refuse a bad ledger path; lock; append one line

```python
def path_is_alias(path: pathlib.Path) -> bool:
    probe = path
    for _ in range(8):
        if probe.is_symlink():
            return True
        probe = probe.parent
        if probe == probe.parent:
            break
    try:
        return path.exists() and path.stat().st_nlink > 1
    except OSError:
        return True


def record_used_nonce(work_real, digest, run_id=None):
    used = used_nonce_path(work_real)
    if path_is_alias(used):
        return
    if not used.parent.exists() or used.parent.is_symlink():
        return
    used.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
    fd = os.open(used, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        st = os.fstat(fd)
        if st.st_nlink > 1 or st.st_uid != os.geteuid():
            return
        data = os.read(fd, 1 << 20).decode(errors="replace")
        if digest in ledger_digests(data):
            return
        os.write(fd, f"{digest} {run_id or '-'} {host_boot_id()}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        used.chmod(0o600)
    except OSError:
        pass
```

`nonce_already_recorded` must take the same flock before it reads.
Refuse a ledger whose resolved path sits under the evidence dir.
This closes R6-symlinked-ledger-dir, R6-ledger-inside-evidence,
R6-rmw-lost-update, R6-parallel-same-nonce, and the O_APPEND race.

A host who can `unlink` the file can still reset it
(R6-delete-host-ledger, R6-empty-ledger-after-crash,
R6-partial-ledger-write, R6-world-writable-ledger-wipe). Optional
hardening: one file per digest under a 0700 directory,
`O_CREAT|O_EXCL`, so a truncate of one name cannot drop the others.

```python
def used_nonce_dir(work_real):
    return used_nonce_path(work_real).with_name(
        used_nonce_path(work_real).name + ".d"
    )

def nonce_already_recorded(work_real, digest):
    slot = used_nonce_dir(work_real) / digest
    if path_is_alias(slot) or path_is_alias(slot.parent):
        return "used-nonces path is a symlink or hardlink"
    if slot.is_file():
        return "nonce was already recorded for this host boot"
    return None
```

### 4. Preboot nlink TOCTOU

Open PREBOOT once with `O_NOFOLLOW`, `fstat` that fd, then read from
it. Do not `stat` one name and `read_text` another.

```python
def read_preboot(preboot: pathlib.Path) -> tuple[str, int]:
    fd = os.open(preboot, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_nlink > 1:
            raise OSError("hardlink")
        return os.read(fd, 1 << 20).decode(), st.st_nlink
    finally:
        os.close(fd)
```

### 5. Clock step-back (false FAIL, not a false PASS)

`run_start > now` fails an honest run if the clock steps back.
Keep that fail-closed. Do not add skew on `run_start`. Say in the
README that a backwards step is a failed host check.

## Exact commands and outputs

```text
python3 /tmp/review-c9-442-r6-src/lab/linux-confine/guest/check-guest-results.test.py -v
# Ran 65 tests in 2.499s
# OK

python3 /tmp/review-c9-442-r6-src/lab/linux-confine/guest/plants-r4.py
# summary: 10 CAUGHT, 0 SURVIVED, 10 plants

python3 /tmp/review-c9-442-r6-src/lab/linux-confine/guest/plants.py
# summary: 43 CAUGHT, 0 SURVIVED, 43 plants

python3 lab/review-c9-442-r6/plants.py
# summary: 18 CAUGHT, 10 SURVIVED, 28 plants
```

Live leftover (timeout nonce on the real host ledger):

```text
# after LC_QEMU_TIMEOUT=2 smoke (wrapper exit 1, checker not run)
# nonce=8b7627491634646ff11c6d0bbbf07de3
# digest fc5fea2e2b3e5ac46f23a8634a0ea016099f633033b19385b059c1afd433caea
# absent from /var/tmp/linux-confine/used-nonces-<boot>.txt
# forged PASS tree + live $WORK/host-preboot.txt
# checker rc=0
# SURVIVED  LIVE-timeout-nonce-forged-pass-default-ledger
```

## Not run here

- native aarch64
- Jetson or any other aarch64 board
- `make-char` / `make-block` (no `CAP_MKNOD`; RESULTS say NOT PROVEN)
- host `date -s` / `libfaketime` clock move (modeled as `run_start=now+30`)

`uname -m` on this machine is `x86_64`.

## Next

Close the timeout record hole and pin `LC_USED_NONCES` on the live
wrapper. Add plants for fresh XDG, host-ledger unlink, a parent
symlink into evidence, a crash-empty ledger, and the live timeout
nonce. Keep native aarch64 / Jetson and `make-char` / `make-block`
as NOT RUN.
