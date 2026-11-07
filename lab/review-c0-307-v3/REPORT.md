# Adversarial review of #307 at 1894f432

Draft only. Do not merge. This folder does not edit `lab/fail-closed-linux/`.

```text
Lane:         lab/review-c0-307-v3
Reviewed:     Elacity/elastos-agent-host-spike#307
Branch:       cursor/fail-closed-linux-0b95
Head:         1894f4323026b6c4df90a3487d8899a4bd8ee1c8
Parent:       637345ac97c9fe2064ddb81b703ee4b69a719df6
              (PID namespace + F03 retarget)
Five-fix:     d234703f then 1894f432 (F25/F26 lib test names)
Tree:         /tmp/review-c0-307-v3-src  (detached worktree)
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64:      NOT RUN
Jetson:       NOT RUN
macOS:        NOT RUN
```

The author applied the five #338 fixes on top of the PID-namespace work
and did not re-run the full `python3 falsify.py`. This session ran the
full crate suite and the full plant list on that exact head.

PID-namespace reapers and a lying-ABI real-rights probe are owned by
`lab/review-c0-307-pidns`. This review does not repeat that work.

## C0 fail-closed on this VM

The unmutated guard is fail-closed on this Linux x86_64, ABI 6 host.

A real `fcl-launch` of the static probe printed `started`, then
`socket_inet errno=1`, `read_outside errno=13`, `storage_write ok`,
`truncate_storage ok`, `truncate_outside errno=13`,
`o_trunc_outside errno=13`, and `nspid=2`. Every refusal row in
`real_kernel` exited 71 and left the probe marker unwritten. The full
plant list, including the silent unconfined restart (F01, F02) and
exec-after-refusal (F03), was caught.

No rebase path starts a provider when a layer fails. The old empty-pipe
start (`got == 0` returned `Ok(pid)` at 637345ac) is gone. Success is
a `ConfineReady` record plus EOF.

## Verdicts on the five #338 fixes

| # | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | Real-kernel row for the per-right floor | **HOLDS** as a mask-path row. Residual: it is the test-only `future_fs` bit (ABI 7), not truncate or `ioctl_dev` missing on this kernel | `real_per_right_floor_refuses_on_this_kernel` with `FCL_TEST_HOOKS=1 --test-require-right future_fs`. F26 CAUGHT. Production rights on a real old ABI stay with `lab/review-c0-307-pidns` |
| 2 | `SimKernel` rejects an access mask outside `handled_fs` | **HOLDS** | `sim_add_path_rule_rejects_access_outside_handled_fs`: ABI 1 ruleset + `STORAGE_ROOT_ACCESS` (includes `TRUNCATE`) → `EINVAL`. F23 CAUGHT |
| 3 | Name the missing right when `--require-landlock-abi` also applies | **HOLDS** | `confine` records the missing-right mask first. `Refusal::new` then adds the extra-floor sentence when `found < floor`. `sim_extra_floor_still_names_the_missing_right` (ABI 4 + require 6 names `ioctl_dev`). `real_extra_floor_still_names_the_missing_right` names `future_fs` and the extra floor. F24 CAUGHT |
| 4 | Probe calls `truncate` and a device `ioctl`, both denied | **WEAK** | `truncate_outside` / `o_trunc_outside` are Landlock `EACCES` (13). Unconfined `truncate` of the same regular file returns 0. `ioctl_dev` is `errno=25` (`ENOTTY`), the same as unconfined `FIONREAD` on `/dev/null`. `test_ioctl_dev_is_landlock.py` FAIL. See below |
| 5 | Empty fault pipe is a refusal, not a start | **HOLDS** | `interpret_fault_pipe(&[], None)` is `Refused(empty_pipe)`. `RealKernel` replaced `got == 0 → Ok(pid)` with that interpreter. `--test-empty-pipe` exits 71 with `the child ended before it wrote a fault or started`. F25 CAUGHT |

## Fix 4, the ioctl row

Linux 6.12 `security/landlock/fs.c` `hook_file_ioctl` uses the rights
stored on the file at open. The fixture opens `/dev/null` in the
unconfined test process, clears `FD_CLOEXEC`, and passes `--device-fd`.
The later Landlock domain does not attach `IOCTL_DEV` to that file.
`FIONREAD` on `/dev/null` is `ENOTTY` with no Landlock.

Live on this head, fd inherited (`close_fds=False`):

```text
unconfined FIONREAD /dev/null          errno=25 ENOTTY
confined  ioctl_dev                    errno=25 ENOTTY
confined  truncate_outside             errno=13 EACCES
unconfined truncate of a regular file  ret=0
```

`real_confined_provider_has_every_layer` accepts any `ioctl_dev errno=`
line. `outside/planted-dev` is a symlink the probe never opens. Seccomp
does not deny `ioctl`. The call happens. The denial is not Landlock.

A Landlock row would open a character device after `restrict_self` on a
path that grants read and omits `IOCTL_DEV`, and would require `EACCES`.

## Rebase fail-open hunt (637345ac → 1894f432)

Conflicts were in `real.rs`, `lib.rs`, `probe/main.rs`, and the tests.
Checked:

| Path | Result |
| --- | --- |
| Empty pipe reported as a start | Closed. `got == 0 → Ok(pid)` removed. Ready record written in `exec` before `execve`. Helper and init close their write-end copies so EOF can arrive |
| Ready record before confine | `Fault::confine_ready()` is written only in `RealKernel::exec`, after `confine` and `detach_into_pid_namespace` |
| Ready then failed `execve` | Parent buffer is 24 bytes. Ready plus an exec fault is `Refused(Execve)` |
| Ready write skipped (`FAULT_PIPE_WRITE < 0`) | `execve` may still run; the parent then sees an empty pipe and refuses |
| `--test-empty-pipe` | Child `_exit(71)` before `confine_and_exec`. Refusal only. Gated on `FCL_TEST_HOOKS=1` |
| `--test-require-right` | `extra_needed_mask \|=` only. It cannot drop truncate or `ioctl_dev`. Unknown without `FCL_TEST_HOOKS=1` (exit 64) |
| F03 after PID insert | Still plants `exec` after a failed `confine`. CAUGHT |
| F18 missing-right skip | Still CAUGHT on the four simulated per-right rows |
| F01 / F02 unconfined restart | Still CAUGHT |
| Stale comment `real.rs:18` | "reapers close it so a successful exec reports an empty pipe" is leftover from 637345ac. The code now needs the ready record. Docs drift, not a launch path |

No new fail-open launch path from the rebase.

## Full crate suite on 1894f432

```text
cd /tmp/review-c0-307-v3-src/lab/fail-closed-linux
export CARGO_TARGET_DIR=$PWD/target
export CARGO_BUILD_BUILD_DIR=$PWD/target/build
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0

cargo fmt -- --check                         clean
cargo clippy --locked --all-targets -- -D warnings   clean
cargo test --locked
  lib          8 passed, 0 ignored
  simulated    17 passed, 0 ignored
  real_kernel  17 passed, 0 ignored
```

## Full `python3 falsify.py` on 1894f432

Command: `python3 -u falsify.py --jobs 4` in the crate. Elapsed 15 s.
Exit 0. `falsifiers: 23/23 caught; controls: 1/1 survived`.

| Plant | Verdict | Named tests that failed (or control) |
| --- | --- | --- |
| C00-noop-control | SURVIVED | 42 tests passed |
| F01-fallback-restarts-unconfined | CAUGHT | 3 simulated + 2 real |
| F02-cli-fallback-runs-unconfined | CAUGHT | 3 real |
| F03-child-execs-after-refusal | CAUGHT | 2 simulated + 2 real |
| F04-userns-error-ignored | CAUGHT | sim + real user-namespace row |
| F05-uid-map-error-ignored | CAUGHT | sim + real id-map row |
| F06-capset-error-ignored | CAUGHT | sim + real capability row |
| F07-bounding-set-not-dropped | CAUGHT | both positive tests |
| F08-no-new-privs-error-ignored | CAUGHT | sim + real no_new_privs row |
| F09-seccomp-error-ignored | CAUGHT | sim + real seccomp row |
| F10-landlock-missing-tolerated | CAUGHT | sim + real Landlock-missing row |
| F11-abi-floor-off-by-one | CAUGHT | extra-floor ABI rows |
| F12-restrict-self-error-ignored | CAUGHT | sim + real ruleset row |
| F13-socket-allowed | CAUGHT | `real_confined_provider_has_every_layer` |
| F14-storage-rule-covers-parent | CAUGHT | `real_confined_provider_has_every_layer` |
| F15-refusal-omits-provider | CAUGHT | one sim + one real |
| F16-refusal-exit-code-not-71 | CAUGHT | `real_landlock_abi_below_required_refuses` |
| F17-gid-map-reported-as-uid-map | CAUGHT | 2 simulated |
| F18-missing-right-silently-passed | CAUGHT | 4 simulated per-right rows |
| F19-pid-unshare-skipped | CAUGHT | confined-layers + host-signal rows |
| F23-sim-ignores-access-mask | CAUGHT | `sim_add_path_rule_rejects_access_outside_handled_fs` |
| F24-extra-floor-hides-missing-right | CAUGHT | sim + real extra-floor-names-right |
| F25-empty-pipe-reported-as-start | CAUGHT | lib empty-pipe + real empty-pipe |
| F26-test-extra-right-ignored | CAUGHT | lib extra-right + sim ABI 6 + real per-right row |

Logs: `/tmp/review-c0-307-v3-src/lab/fail-closed-linux/target/falsify/<id>.log`.

This folder's own plant: `python3 -I lab/review-c0-307-v3/test_ioctl_dev_is_landlock.py` → FAIL (ioctl errno matches unconfined ENOTTY).

## C0 Linux half

**NOT BOOKABLE.**

The launch path on this ABI 6 x86_64 host is fail-closed. Fixes 1, 2, 3
and 5 hold. The author claim that the full falsify list was not re-run
is now closed: 23/23 CAUGHT, control SURVIVED.

C0's Linux half still has an open measurement: the #338 ioctl row does
not prove `ioctl_dev`. The real-kernel per-right row proves the extra-bit
hook, not a missing truncate or `ioctl_dev` on a real old ABI. Book after
the ioctl probe requires Landlock `EACCES`, and after the pidns review's
lying-ABI real-rights probe (or a board ABI 1–4 run) covers the production
rights.

## Not run here

- aarch64 execution: NOT RUN. The `aarch64-unknown-linux-gnu` rustup target
  is not installed on this VM. No qemu, no `binfmt_misc`.
- Jetson / Linux 5.15: NOT RUN.
- macOS: NOT RUN.
- Real provider binaries: NOT RUN. The stand-in is the static probe.

This VM's `/usr/include/linux/landlock.h` still has no `IOCTL_DEV` and no
`SCOPE_*`. The running kernel reports Landlock ABI 6. The uapi oracle
remains Linux 6.12, as in #338.

## For Sash or Anders

1. Treat `ioctl_dev errno=` as a Landlock proof, or accept that the probe
   only shows the syscall ran. Today it shows `ENOTTY`.
2. Keep `future_fs` as the ABI 6 stand-in for the mask path, or wait for
   the pidns lying-ABI probe before booking C0.
3. The leftover `real.rs` comment about an empty pipe meaning a successful
   exec should match the ready-record contract.

## Principles

- 3 No ambient authority: a failed layer still starts nothing.
- 11 Fail closed, then explain: empty pipe and missing rights name the
  reason. The ioctl test line names a denial the kernel did not make.
- 12 Docs, code, tests, and operations must agree: README says the probe
  shows device ioctl denied. The line is `errno=25`, same as unconfined.
