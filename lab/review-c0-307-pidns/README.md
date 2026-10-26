# lab/review-c0-307-pidns

Independent adversarial review of draft PR
https://github.com/Elacity/elastos-agent-host-spike/pull/307
(C0 fail-closed Linux guard, PID namespace at `758d3f80`).

Draft only. Do not merge. This folder is the only tree this session
writes. `lab/fail-closed-linux/` was not edited. Branch
`cursor/fail-closed-linux-0b95` was not pushed.

```text
Lane:           lab/review-c0-307-pidns
Reviewed PR:    Elacity/elastos-agent-host-spike#307
Named head:     637345ac97c9fe2064ddb81b703ee4b69a719df6
                parent 758d3f805a40ade6cfd47d9e3a390921c47207a6
Moved head:     1894f4323026b6c4df90a3487d8899a4bd8ee1c8
                (d234703f then 1894f432; #338 gap fixes)
Trees:          /tmp/fcl-637345ac/lab/fail-closed-linux
                /tmp/fcl-1894f432/lab/fail-closed-linux
Machine:        Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28),
                Landlock ABI 6, uid 1000, no YAMA
Aarch64:        NOT RUN
Jetson:         NOT RUN
```

`637345ac` is the named PID-namespace head. While this review ran, the
same branch moved to `1894f432`. Both heads are named below. Counts
come from commands in `evidence/`.

## Re-run on 637345ac

From a writable copy of that commit (not the #307 branch):

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          6 passed; 0 failed; 0 ignored
  simulated   14 passed; 0 failed; 0 ignored
  real_kernel 13 passed; 0 failed; 0 ignored
python3 falsify.py
  falsifiers: 19/19 caught; controls: 1/1 survived
  C00-noop-control: 33 tests passed
F19 nspid after skip: 6657 and 6658 (host pids, not 1 or 2)
```

The claimed counts on `637345ac` hold on this host.

## Re-run on 1894f432 (branch moved)

`d234703f` closes the five #338 gaps. `1894f432` only fixes F25/F26
plant names (`lib::tests::...`).

```text
cargo fmt -- --check                         exit 0
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          8 passed; 0 failed; 0 ignored
  simulated   17 passed; 0 failed; 0 ignored
  real_kernel 17 passed; 0 failed; 0 ignored
python3 falsify.py
  falsifiers: 23/23 caught; controls: 1/1 survived
  C00-noop-control: 42 tests passed
```

Empty fault pipe is now a refusal (`interpret_fault_pipe`,
`ConfineReady` written in `exec` just before `execve`). The PID
namespace order is unchanged.

## Verdicts

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-T1 | lib 6, simulated 14, real_kernel 13, 0 ignored on `637345ac` | **HOLDS** | `evidence/cargo-test.txt` |
| C0-T2 | falsify 19/19 caught, control survived | **HOLDS** | `evidence/falsify.txt`; F19 printed host `nspid=6657` / `6658` |
| C0-T3 | same suites on `1894f432` stay green | **HOLDS** at the new counts 8 / 17 / 17, falsify 23/23 | `evidence/1894-cargo-test.txt`, `evidence/1894-falsify.txt` |
| C0-P1 | `unshare(CLONE_NEWPID)` after the user maps, then refuse with `the PID namespace cannot be created` | **HOLDS** | `confine` order in `src/lib.rs`; `real_pid_namespace_unavailable_refuses` and `sim_pid_namespace_unavailable_refuses` passed |
| C0-P2 | a second fork makes PID-1 init; the provider is PID 2 | **HOLDS** | live tree: helper `NSpid=7088`, init `7089 1`, provider `7090 2`, probe `nspid=2` (`evidence/pidns-attack.json`) |
| C0-P3 | the two reaper processes run after the user namespace and before capability drop, `no_new_privs`, seccomp and Landlock | **FALSIFIED** as a statement about the forks | `unshare_pid` is inside `confine`, before cap drop. `detach_into_pid_namespace` (the two forks) runs after `confine` returns. Live helper already has `NoNewPrivs=1`, `Seccomp=2`, all `Cap*=0` |
| C0-P4 | `launch` returns a pid the host can use to stop the provider | **WEAK** for SIGTERM, **FALSIFIED** for SIGKILL | `launch` returns the helper (host PID ns). SIGTERM is forwarded on the happy path (`real_reaper_forwards_signal` passed). SIGKILL of that pid left init and the provider alive; `fcl-launch` exited 137 (`evidence/pidns-attack.json`) |
| C0-P5 | a confined child `kill` of a host pid is ESRCH | **HOLDS** for the provider | probe `kill(host, 0)` is ESRCH/EPERM because the provider is in the new PID ns. The helper stays in the host PID ns. `kill` is not on the seccomp deny-list. ABI 6 `SCOPE_SIGNAL` is what should stop the helper; ABI 5 still cannot set that bit |
| C0-P6 | an empty fault pipe after detach cannot look like a start | **FALSIFIED** on `637345ac`; **HOLDS** for empty reads on `1894f432` | `637345ac` `got == 0` returns `Ok(pid)`. Lab demo: `empty_pipe_reported_as_start pid=7106`. `1894f432` refuses an empty read. A `ConfineReady` record with no `execve` is still treated as a start |
| C0-P7 | init reaps everything in the PID namespace | **FALSIFIED** | init `waitpid`s only the provider. A forked child of the provider stayed `Z` under the provider (pid 7099). A daemonize (`fork` + parent exit) made `fcl-launch` exit 0 and the grandchild was gone (PID 1 exited, namespace torn down) |
| C0-A1 | the per-right floor trusts the ABI number | **HOLDS** | `missing_required_mask(5)` is `None`. No `landlock_can_handle_fs`. This review's crate: current launches, patched refuses |
| C0-A2 | a lying ABI 5 / ABI 1 rights kernel launches | **HOLDS** on `SimKernel` and the policy function | `F-LYING-CURRENT` launched on reported ABI 5. `proposal.patch` then refused. Dropping the probe launched again. 3/3. A real kernel that rejects unknown `create_ruleset` bits already fail-closes at `CreateRuleset` with a generic EINVAL |
| C0-A3 | ABI-5 `LANDLOCK_SCOPE_SIGNAL` is a named gap | **HOLDS** | `scoped_for_abi(5) == 0`. This host is ABI 6, so the gap was not executed here |

## Reaper-process finding

The helper and init are not a pre-drop window.

`confine` does: user ns, maps, `unshare(CLONE_NEWPID)`, then capability
drop, `no_new_privs`, seccomp, Landlock. `confine_and_exec` calls
`confine`, then `detach_into_pid_namespace`, then `exec`. The two
reaper processes are forks of a process that already applied every
layer. `tests/source_order.rs` pins that order. The live helper
`/proc/<pid>/status` matches: caps zero, `NoNewPrivs=1`, `Seccomp=2`.

What those processes can do after the forks:

| Check | Helper (returned pid) | Init (PID 1 in the new ns) | Provider (PID 2) |
| --- | --- | --- | --- |
| PID namespace | host (same inode as the test) | new | new |
| caps / nnp / seccomp / Landlock | inherited, all applied | inherited | inherited |
| `ptrace` | denied by seccomp | denied | denied |
| `kill` | allowed by seccomp; sees host pids | allowed; sees only the new ns | allowed; sees only the new ns |
| files | storage root + executable | same | same |

`launch` / `fcl-launch` print the helper pid. SIGTERM is forwarded
(`SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`, `SIGUSR1`, `SIGUSR2`,
`SIGALRM`) after `REAP_CHILD` is stored. SIGKILL is not forwarded.
Killing the helper with SIGKILL does not stop the provider.

Init is not a general reaper. It `waitpid`s one child. Unreaped
children of the provider stay zombies. If the provider exits after a
`fork`, init exits too and the kernel tears the namespace down.

Signal races: handlers are installed inside `reap_forever`, after the
fork and after `close_fault_write`. A SIGTERM in that window hits
default disposition on the helper. PID 1 ignores unhandled SIGTERM
until init installs its own handlers.

Exit status: each reaper `_exit`s `WEXITSTATUS` or `128 + signal`.
`fcl-launch` then `waitpid`s the helper. A signaled provider becomes a
normal exit 143 on the helper, not `WIFSIGNALED` on the returned pid.

Fault pipe after detach:

- On `637345ac`, helper and init close the write end, then wait. If
  they die before the provider writes, the parent sees an empty pipe
  and reports a start. The lab C demo reproduced that protocol.
- On `1894f432`, an empty read is a refusal. `exec` writes
  `ConfineReady` immediately before `execve`. A death after that write
  and before `execve` still looks like a start.

## Lying-ABI proposal

Not applied to #307. The patch is `proposal.patch` against
`637345ac`. A dry-apply on `1894f432` failed two hunks in `src/lib.rs`
because that head already added `Step::ConfineReady`.

The idea: after the ABI-number check, try-create a ruleset that
handles only `truncate`, then only `ioctl_dev`. `EINVAL` means the
kernel does not have that right. The refusal names the right and
`landlock_create_ruleset returned EINVAL (reported ABI N)`.

This review crate models that policy (`src/lib.rs`):

```text
cargo test --locked
  lib 5 passed; lying_abi 1 passed; source_order 6 passed; 0 ignored
```

Falsifier (`python3 falsify.py`), on a copy of `637345ac`:

```text
F-LYING-CURRENT  CAUGHT  current code launched on reported ABI 5
F-LYING-PATCHED  CAUGHT  patched code refused the lying ABI 5 kernel
F-LYING-DROP     CAUGHT  removing the probe makes the liar launch again
lying-abi falsifiers: 3/3 caught
```

A kernel that accepts the extra bits and does not enforce them is
still uncaught. The probe only sees `EINVAL`. A functional
truncate/ioctl check is separate work. `1894f432` already has the
probe call those operations; it still decides launch from the ABI
number.

## This folder

| Path | Why |
| --- | --- |
| `README.md` | this report |
| `proposal.patch` | rights-probe patch for `637345ac` only |
| `src/lib.rs`, `tests/lying_abi.rs` | current vs patched policy |
| `tests/source_order.rs` | PID-namespace order against `FCL_SRC` |
| `attack_pidns.py`, `probes/` | live helper / SIGKILL / zombie / daemonize / empty-pipe |
| `falsify.py`, `mutants/` | lying-ABI plants |
| `check.py`, `tests/test_review.py`, `run.sh` | detectors |
| `evidence/` | command output used in the table |

`lab/review-c0-307/run.sh` from this folder:

```bash
lab/review-c0-307-pidns/run.sh
```

Needs `FCL_SRC` (default `/tmp/fcl-637345ac/lab/fail-closed-linux`)
and the built `fcl-launch` / `fcl-probe` from that extract.

## Not run

- aarch64 execution. Compile check was not repeated here.
- Jetson. No board.
- Real provider binaries. The stand-in is the static probe or the
  lab C programs.
- Mount, network and IPC namespaces. Not layers of this guard.
- ABI-5 `LANDLOCK_SCOPE_SIGNAL`. This host reports ABI 6.

## Principles

- 3: the helper still has host PID-namespace visibility. ABI 6 scope
  is the current stop for helper `kill`; ABI 5 does not have it.
- 11: a missing PID namespace already refuses by name. A lying ABI
  number still launches unless the rights are probed.
- 12: `637345ac` counts match the PR. `1894f432` changed the empty
  pipe rule; the README on that head should stay the source for that
  claim.

DeepSeek: none.

## Next

The PID-namespace forks are after the drop. The remaining work is the
returned pid (SIGKILL / daemonize / init `waitpid(-1)`), a rights
probe that does not trust the ABI number, and the ABI-5 scope gap.
`proposal.patch` is for `637345ac`; rebase it before anyone puts it
on #307. This PR stays draft.
