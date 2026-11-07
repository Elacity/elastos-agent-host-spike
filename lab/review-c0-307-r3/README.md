# lab/review-c0-307-r3

Independent adversarial review r3 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux launch) at `26c55e6c`.

Draft only. Do not merge. This folder is the only tree this session
writes. `lab/fail-closed-linux/` was not edited. Branch
`cursor/fail-closed-linux-0b95` was not pushed.

```text
Lane:           lab/review-c0-307-r3
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Head:           26c55e6cbd59d1f4e740fc60dc8dd404b7d900da
Parent:         457914bf3e0e77c89565b4a6bbb33587d5d616f1
Tree:           /tmp/review-c0-307-r3-src  (detached worktree)
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28),
                Landlock ABI 6, uid 1000
Aarch64:        cargo check only (Finished); no aarch64 execution
Jetson:         NOT RUN
```

## Plain English

The #355 and #357 holes on this head are closed on this Linux x86_64
ABI 6 host.

`launch` now returns the PID-namespace init. The helper writes that
host pid and exits. SIGKILL or SIGTERM of that pid takes the namespace
down, including a provider that ignores SIGTERM and a grandchild that
did double-fork plus `setsid`. Init reaps orphans. A `ConfineReady`
record without `execve` is a refusal. The ioctl row is now a real
Landlock denial: unconfined `TIOCGWINSZ` on the pty works, confined
open-after-restrict is `EACCES` 13.

The claimed suite counts match on this machine: lib 8, simulated 18,
real_kernel 22, all green, none ignored. `falsify.py` is 28/28 caught
and the control survived with 48 tests. Re-breaking F25, F27, F28,
F29, F31 and F32 makes those named tests fail again.

C0 on Linux x86_64 ABI 6 is bookable. aarch64 execution and Jetson
are still open. Three residuals stay named: the start pipe proves
that every write end closed, not that `execve` ran; Landlock ioctl
rights attach at open, so an inherited pre-confine pty fd still
accepts `TIOCGWINSZ`; the rights probe only sees `EINVAL`, so a
kernel that accepts a bit and ignores it still launches.

## Re-run of the claimed suites

From `/tmp/review-c0-307-r3-src/lab/fail-closed-linux` at `26c55e6c`:

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          8 passed; 0 failed; 0 ignored
  simulated   18 passed; 0 failed; 0 ignored
  real_kernel 22 passed; 0 failed; 0 ignored
python3 falsify.py --jobs 4
  falsifiers: 28/28 caught; controls: 1/1 survived
  C00-noop-control: 48 tests passed
cargo check --locked --target aarch64-unknown-linux-gnu --all-targets
  Finished (check only; no aarch64 execution)
```

Evidence: `evidence/official-suite.txt`, `evidence/falsify.txt`,
`evidence/aarch64-check.txt`.

## Verdicts on the claimed fixes

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 8, simulated 18, real_kernel 22, 0 ignored | **HOLDS** | `evidence/official-suite.txt` |
| C0-T2 | falsify 28/28 caught, control survived 48 tests | **HOLDS** | `evidence/falsify.txt` |
| C0-P3 | no host-namespace helper beside the provider; returned pid is init | **HOLDS** | live `NSpid` `8352 1`, provider `8353 2`, launcher children `[8352]`. F27 CAUGHT on re-break |
| C0-P4 | SIGKILL or SIGTERM of the returned pid takes the namespace down | **HOLDS** | SIGKILL → launcher 137, init and provider gone. SIGTERM of a SIGTERM-ignoring stand-in → launcher 143, children gone. F27 CAUGHT |
| C0-P6 | ConfineReady without execve is a refusal; empty early death is a refusal | **HOLDS** | `--test-confine-ready` exit 71, no marker. `--test-empty-pipe` exit 71. F25 CAUGHT |
| C0-P7 | init `waitpid(-1)` reaps; daemonize keeps the namespace | **HOLDS** | daemonize left grandchild 8363 under init; SIGKILL of init removed it; launcher stayed up until that kill. F28 and F29 CAUGHT |
| C0-PDEATH | provider has `PR_SET_PDEATHSIG` | **HOLDS** | stand-in printed `pdeathsig=9` (SIGKILL) |
| C0-ABI | try-create each needed right; EINVAL is a named `right_probe` | **HOLDS** for EINVAL | `--test-lie-rights` names truncate, ioctl_dev, and `landlock_create_ruleset returned EINVAL (reported ABI 6)`. F31 CAUGHT. Silent-ignore residual below |
| C0-IOCTL | pty `TIOCGWINSZ` unconfined ok, confined EACCES 13 | **HOLDS** for an open after confine | confined `ioctl_dev errno=13`, unconfined ioctl on the same slave succeeded. F32 CAUGHT. Inherited-fd residual below |

## Replay of #355 and #357

These are the same attacks as the earlier reviews, on this head.

| Old finding | This head |
| --- | --- |
| P3 helper in the host PID ns, could see host pids | Returned pid is in the new PID ns (`NSpid` ends in 1). Launcher children are only init. |
| P4 SIGKILL of the returned pid left the provider alive | SIGKILL of init: provider gone, launcher 137 |
| P6 ConfineReady without execve looked like a start | Exit 71, `ConfineReady without execve is not a start`, no marker |
| P7 init reaped only the first child; daemonize tore the ns down | Daemonize kept the grandchild; init death then tore it down |
| #357 ioctl ENOTTY both ways | Confined EACCES 13; unconfined TIOCGWINSZ ok |

## New attacks

| Attack | Result | Verdict |
| --- | --- | --- |
| Pid reuse between helper exit and caller kill (20 launches) | Every returned pid was init (`NSpid` … `1`). Helper was already gone. Caller kill hits init. | **HOLDS** |
| Double-fork + `setsid` | Grandchild stayed in the new PID ns (`NSpid` 4). SIGKILL of init removed it. `setns` is on the seccomp deny list. | **HOLDS** |
| Provider ignores SIGTERM | SIGTERM on init still SIGKILLs the namespace (`init_take_down`). Launcher 143. | **HOLDS** |
| `execve` of `/bin/sleep` (dynamic) | Landlock EACCES 13: no library grant. Refusal, no start. | expected |
| `execve` of a second static stand-in that writes nothing | Start accepted. The pipe only sees EOF. | **WEAK** as a binary-identity proof; the granted path is what ran |
| Inherited pty fd opened before confine, then `TIOCGWINSZ` | `inherit_ioctl ok`. Landlock stores ioctl rights at open. | **survives** (named fd-inheritance gap) |
| Close the fault write end instead of `execve` (trusted-helper plant) | `started` with no `probe-ran` marker. | protocol **WEAK**: EOF means the write ends closed |
| Close the pipe before confine, then continue (plant) | Start still happened and the probe ran. EOF can arrive before `execve`. | timing **WEAK** |
| Grandchild holds the write end (plant) | `launch` blocks. The provider is already running. Kill of init then returns 137 because `kill(pid,0)` is true on the zombie. | leaked write end hangs start reporting; kill-during-hang is messy |
| Kernel accepts the ruleset bit and ignores the right | Probe only looks for `EINVAL`. SimKernel has no ioctl check after a pass. | **WEAK** / residual |

Live JSON: `evidence/attacks.json`. Plants and re-breaks: `evidence/rebreak.json`.

## Re-break of each claimed falsifier

Copies of the crate only. The #307 branch was left alone.

| Plant | Named tests | This session |
| --- | --- | --- |
| F25 ConfineReady is a start | lib ready-record + real confine-ready | CAUGHT |
| F27 helper is the returned pid | SIGKILL teardown + confined-layers | CAUGHT |
| F28 init exits on first child | daemonize row | CAUGHT |
| F29 init never `waitpid(-1)` | orphan-grandchild row | CAUGHT |
| F31 skip the rights probe | sim lying ABI + real `--test-lie-rights` | CAUGHT |
| F32 drop `IOCTL_DEV` from `handled_fs` | confined-layers (ioctl must be 13) | CAUGHT |

## Residuals that stay open

1. **Start pipe.** The parent treats empty EOF plus a live init pid as a
   start. That matches close-on-exec after `execve` when the helper and
   init have closed their copies. A close in the trusted helper, without
   `execve`, produces the same EOF. C0 still trusts that helper.
2. **Inherited descriptors.** The guard does not close fds the provider
   inherits. A pty opened before `restrict_self` still accepts
   `TIOCGWINSZ`. The README already marks this as not covered. The new
   ioctl row is honest for opens after confine.
3. **Silent-ignore ABI.** `landlock_can_handle_fs` is a `create_ruleset`
   try. `EINVAL` is a named refusal. A kernel that accepts the bit and
   does not enforce it still launches. This host is ABI 6 and does
   enforce `ioctl_dev` on a post-confine open.

## C0 bookable?

**Yes, for Linux x86_64 Landlock ABI 6, apart from aarch64 and Jetson
execution.**

The #355 reaper / start-pipe / lying-EINVAL holes and the #357 ioctl
measurement are closed on this host. The three residuals above are
named limits, not a fail-open launch path on the production helper.

Still open for a full C0 book: run the same real-kernel rows on
aarch64, and run them on a 5.15-class Jetson (that board should
refuse every provider and name `truncate` / `ioctl_dev`).

## This folder

| Path | Why |
| --- | --- |
| `README.md` | this report |
| `attack.py` | live #355 / #357 / new attacks against the built `fcl-launch` |
| `rebreak.py` | official F25/F27/F28/F29/F31/F32 plus three helper plants |
| `standins/*.c` | SIGTERM-ignore, double-fork, inherited ioctl, pdeathsig, sleep |
| `run.sh` | build stand-ins, then both scripts |
| `evidence/` | command output used in the tables |

```bash
lab/review-c0-307-r3/run.sh
```

Needs `FCL_SRC` (default `/tmp/review-c0-307-r3-src/lab/fail-closed-linux`)
and that tree's built `fcl-launch` / `fcl-probe`.

## Principles

- 3: the returned process is the PID-namespace init. Host-pid signalling
  from the provider stays inside that namespace. Inherited fds still
  carry the opener's Landlock rights.
- 11: a missing right, a `ConfineReady` record, and an early empty pipe
  each name a refusal. EOF plus a live init is the start rule.
- 12: the README counts (8 / 18 / 22, falsify 28/28) match this run.

DeepSeek: none.

## Next

Keep #307 draft. Book the Linux x86_64 ABI 6 half if the residuals
above are accepted. aarch64 execution and a Jetson ABI-1 run are the
remaining C0 machines.
