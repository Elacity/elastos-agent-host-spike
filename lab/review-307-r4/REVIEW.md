# Independent adversarial review r4 of C0 (#307)

Independent adversarial review r4 of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux launch) at `dc5fe676`.

Draft only. Do not merge this review PR. This folder is the only tree
this session writes. `lab/fail-closed-linux/` was left as the author
wrote it. Branch `cursor/fail-closed-linux-0b95` was not pushed.

```text
Lane:           lab/review-307-r4
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Head:           dc5fe676e8ad13e5882871a27b9f2dd166780bf5
Parent:         634d3d6b (sample-exe / identity-fd series)
Tree:           /tmp/review-c0-307-r4-src  (detached worktree)
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28),
                Landlock ABI 6, uid 1000
Aarch64:        cargo check only (Finished); no aarch64 execution
Jetson:         NOT RUN
```

## Plain English

The three r3 leftovers are closed on this Linux x86_64 ABI 6 host.

Start is now two things: a quiet fault pipe, and a parent-side sample of
`/proc/<provider pid>/exe` that matches the device and inode `stat` saw
before fork. Closing the pipe without `execve` leaves the helper image
in place and is a refusal. A silent expected binary is a start.

Before confine and exec the helper runs `close_range` and keeps only
stdin, stdout, stderr, the fault pipe, and a short keep list. An extra
pre-confine pty on fd 3 is gone (`EBADF`). A pre-confine pty that arrives
as stdin stays, because fd 0 is on the allowlist. `TIOCGWINSZ` on that
stdin still works.

After `landlock_restrict_self` a throwaway child, in the same Landlock
domain, tries a write outside the root, a truncate of that file, and
`TIOCGWINSZ` on a fresh pty the plan already granted for read. This
host denied the write-open, the truncate, and the ioctl (`EACCES`). The
parent trusts that child's exit status through `waitpid`. The child is
still the trusted helper, before `execve`.

The claimed suite counts match: lib 9, simulated 19, real_kernel 26, all
green, none ignored. `falsify.py` is 31/31 caught and the control
survived with 54 tests. Re-planting F33, F34 and F35 on copies made
those named tests fail again.

C0 launch-fail-closed is still bookable on this host. Two new leftovers
stay named: the start sample is once, and `memfd_create` plus
`execveat(AT_EMPTY_PATH)` then runs a second image; a pre-confine pty
on stdin still accepts ioctl. aarch64 execution and Jetson are still
open.

## Re-run of the claimed suites

From `/tmp/review-c0-307-r4-src/lab/fail-closed-linux` at `dc5fe676`:

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          9 passed; 0 failed; 0 ignored
  simulated   19 passed; 0 failed; 0 ignored
  real_kernel 26 passed; 0 failed; 0 ignored
python3 falsify.py --jobs 4
  falsifiers: 31/31 caught; controls: 1/1 survived
  C00-noop-control: 54 tests passed
cargo check --locked --target aarch64-unknown-linux-gnu --all-targets
  Finished (check only; no aarch64 execution)
```

Evidence: `evidence/official-suite.txt`, `evidence/falsify.txt`,
`evidence/aarch64-check.txt`.

The author's "31/31 + 1 control" holds. The control suite is 54 tests
(9 + 19 + 26). That is the current crate, not the 48-test control from
r3.

## Verdicts on the claimed r3 fixes

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 9, simulated 19, real_kernel 26, 0 ignored | **HOLDS** | `evidence/official-suite.txt` |
| C0-T2 | falsify 31/31 caught, control survived | **HOLDS** | `evidence/falsify.txt` (control 54 tests) |
| R3-1 | start = quiet pipe AND `/proc/exe` dev+inode; identity fd across `execve` | **HOLDS** as a start rule | `--test-close-pipe` exit 71, `exec_identity`. F35 CAUGHT. Silent expected binary starts. |
| R3-2 | `close_range` on every fd except an allowlist before confine/exec | **HOLDS** for extra fds | F33 CAUGHT: skipping `close_fds` leaves `inherit_ioctl ok` on fd 3. Live `close_range` on this host. Stdin leftover below. |
| R3-3 | post-`restrict_self` child tries write-outside, truncate, ioctl; any success refuses | **HOLDS** for the ops it can reach | strace: write-open `EACCES`, truncate `EACCES`, `TIOCGWINSZ` `EACCES`. F34 CAUGHT. |

## Re-plant of F33, F34, F35

Copies only. The #307 branch was left alone. Each plant is the official
mutant text, applied by this session's `replant.py`.

| Plant | Named tests | This session |
| --- | --- | --- |
| F33 skip `close_unneeded_fds` | `real_inherited_pty_ioctl_is_not_available` | CAUGHT. Inherited fd 3: `inherit_ioctl ok` |
| F34 skip `enforcement_self_test` | sim + real lying-enforcement | CAUGHT. Sim starts; real exit 0 instead of 71 |
| F35 ignore a mismatched `/proc/exe` | `real_close_pipe_without_exec_is_not_a_start` | CAUGHT. Close-pipe reported `started`, exit 0 |

Evidence: `evidence/replant.txt`. Official `falsify.py` also caught all
three in the 31/31 run.

## New hunts

Live against the built `fcl-launch` at this head. JSON: `evidence/attacks.json`.

### Later re-exec after the parent samples `/proc/exe`

The parent samples children of init while the fault pipe is still open,
then once more after EOF. After a match it acks init and never looks
again. `fcl-launch wait()` is `waitpid` on init. Seccomp is a deny-list
and leaves `execve`, `execveat` and `memfd_create` allowed.

| Attack | Result | Verdict |
| --- | --- | --- |
| Expected binary, then `execve` of a second static file outside the root | Start accepted. Second `execve` `EACCES` 13. `/proc/exe` still hunter. | path exec **denied** |
| Write a payload under storage, then `execve` that path | Start accepted. `EACCES` 13. Storage has no `EXECUTE`. | storage exec **denied** |
| Same path, new inode (rename over the running file) | inode 423739 → 423740. `execve` of that path `EACCES` 13. `/proc/exe` is `(deleted)`. | swapped inode **denied** |
| Host bind-mount over the path | `mount` errno 1 (`EPERM`). This uid has no `CAP_SYS_ADMIN`. | **NOT RUN** on the host |
| Read the storage payload into a memfd, `execveat(AT_EMPTY_PATH)` | Start accepted. Next stdout line is `payload pid=2`. | second image **ran** |

So: exe is not re-checked, and there is no "no further execve" seccomp
rule. Landlock stops a second *path*. It does not stop a memfd image.
The start proof is a snapshot. A provider that is the expected binary
can then become another binary and keep the same sandbox.

### Identity fd left open into the provider

The identity object is a pipe, not an `O_PATH` of the executable. Helper
and init close their write ends. The provider keeps the write end
(`FD_CLOEXEC` cleared) so `/proc/<pid>/exe` stays visible while the
parent still holds the read end. After the sample the parent closes the
read end.

Live `listfds`: fd 0/1/2 are the usual pipes, plus **fd 11, flags=0,
kind=pipe**. That is the leftover identity write end. It is not a
ruleset, not `/proc`, not a pty. After the parent closes the read end
it is a broken pipe. A write there raises `SIGPIPE`. It is a leak of an
extra fd, not a privileged fd.

### Allowlist fds

Kept: 0, 1, 2, fault write (cloexec), handoff write, ack read, identity
write. strace on this host: `close_range` ran; `/proc/self/fd` did not.

| fd | Abuse on this host |
| --- | --- |
| 0 as a pre-confine pty | `ioctl_fd_0 ok` (`TIOCGWINSZ`). Landlock ioctl rights are fixed at open. F33 only covers fd 3. |
| 1, 2 as pipes | `ENOTTY` 25 |
| 11 identity pipe | `ENOTTY` 25. Broken pipe after the sample. |

A launcher whose stdin is a terminal still hands the provider a live
ioctl-capable pty. That is the r3 inherited-pty leftover, now limited
to the allowlist.

### `close_range` fallback when `/proc` is missing

This kernel has `close_range`. The live launcher used it. The
`/proc/self/fd` walk is source-only here. `ENOSYS` goes to that walk.
If `open("/proc/self/fd")` fails, `close_unneeded_fds` returns the
errno and confine refuses. A missing `/proc` fails closed. A lying
`/proc` is outside this lab: there is no mount namespace, so `/proc` is
the host's.

### Self-test: channel, domain, rights

strace of one successful launch (pids: parent 11634, helper 11635,
self-test child 11638):

- Helper adds a Landlock read rule on `/dev/pts/3` (`O_PATH`).
- Self-test child, after `restrict_self` and after `close_range`:
  - `open` of `/tmp/fcl-enf-…/probe` `EACCES`
  - `truncate` of that path `EACCES`
  - `open` of `/dev/pts/3` succeeds (the extra read grant)
  - `ioctl(…, TIOCGWINSZ)` `EACCES`
- Parent `waitpid`s that child. Exit 0 is "every denied op failed."
  Any other status is `ENFORCEMENT_BROKEN`.

The channel is the child's own exit code. The child is the trusted
helper, before `execve`. The provider never writes that status. The
child runs in the same Landlock ruleset the provider will keep.

Write-outside is an open that already failed, so the `write` is not
reached. Truncate is a real pathname `truncate`. Ioctl is a real
post-confine open-plus-ioctl, because `Plan` puts the pty on
`extra_read`.

Rights the profile handles and this self-test leaves untouched:

| Right | Why it is out of the self-test |
| --- | --- |
| `REFER` | Not a needed launch right. Kernel deny-by-absence is the story. |
| `MAKE_CHAR` / `SOCK` / `FIFO` / `BLOCK` / `SYM` | Handled, not granted on storage, not probed. |
| TCP bind/connect (ABI 4+) | Handled, not granted. Seccomp already denies `socket`. |
| `EXECUTE` of a non-path image | Handled. memfd `execveat` still ran. |
| `LANDLOCK_SCOPE_SIGNAL` | Set on ABI 6. No self-test that a cross-namespace signal is denied. |

`--test-lie-enforcement` only makes the helper return `EBADE`. It does
not prove the three ops. F34 proves the call is present. The strace
above is what proves the ops ran on this kernel.

## C0 bookable?

**Yes, for Linux x86_64 Landlock ABI 6, as a launch-fail-closed guard,
with the leftovers below named.**

The r3 start-pipe, extra-fd, and silent-ignore holes the author claimed
to close are closed on this host. Launch still refuses a quiet pipe
that is not the expected image, an extra inherited pty, and a helper
that skips the self-test.

Still open for a full C0 book:

- aarch64 execution of the real-kernel rows (this session only compiled)
- a 5.15-class Jetson run (that board should refuse every provider and
  name `truncate` / `ioctl_dev`)
- a named decision on memfd/`execveat`: either deny `execve` after
  start, or say "the granted path is the only *path* that can run"
- a named decision on stdin/stdout/stderr: close them too, or replace
  them with fresh pipes, if inherited ioctl is in scope

## Residuals that stay open

1. **Start sample is once.** After ack, a later `execve` of another
   path is Landlock-denied. A later memfd `execveat` runs. Seccomp
   allows it.
2. **Allowlist includes 0, 1, 2.** A pre-confine pty on stdin still
   accepts `TIOCGWINSZ`. Extra fds are closed.
3. **Identity write end stays in the provider** as an extra pipe
   (fd 11 here). Not a privileged fd.
4. **`close_range` fallback** is unused on this host. Source fails
   closed when `/proc/self/fd` cannot be opened.
5. **Self-test covers write-open, truncate, and ioctl.** It does not
   cover `EXECUTE` on anonymous files, `REFER`, `make_*`, or network.
6. **Bind-mount of the executable** was `EPERM` on this uid. Path
   replace after start is denied by inode. Bind-mount *before* `stat`
   would be "the path the caller asked to run."

## This folder

| Path | Why |
| --- | --- |
| `REVIEW.md` | this report |
| `README.md` | pointer |
| `attack.py` | live hunts against the built `fcl-launch` |
| `replant.py` | independent F33 / F34 / F35 plants on copies |
| `standins/hunter.c`, `payload.c` | static stand-ins |
| `run.sh` | hunts then replant |
| `evidence/` | official suite, falsify, aarch64 check, attacks, replant |

```bash
lab/review-307-r4/run.sh
```

Needs `FCL_SRC` (default `/tmp/review-c0-307-r4-src/lab/fail-closed-linux`)
and that tree's built `fcl-launch`.

## Principles

- 3: the returned process is PID-namespace init. The provider keeps
  only the allowlist plus a leftover identity pipe. A stdin pty still
  carries the opener's ioctl right.
- 11: a mismatched `/proc/exe`, a skipped self-test, and a successful
  denied op each refuse the launch. A later memfd image is outside
  that start rule.
- 12: the README counts (9 / 19 / 26, falsify 31/31) match this run.

DeepSeek: none.

## Next

Keep #307 draft. Book the Linux x86_64 ABI 6 launch half if the
leftovers above are accepted. Say what "only this binary" means for
memfd. Run the real-kernel rows on aarch64, and on a Jetson ABI-1
board.

**VERDICT: PASS** on the three claimed r3 fixes at `dc5fe676`.
New leftovers are named, not a fail-open launch on this host.
