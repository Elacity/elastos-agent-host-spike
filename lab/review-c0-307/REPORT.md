# Adversarial review of #307 and #320

Draft only. Do not merge. This folder does not edit `lab/fail-closed-linux/`
or `lab/jetson-proof-kit/`.

```text
Lane:         lab/review-c0-307
Reviewed:     Elacity/elastos-agent-host-spike#307 and #320
#307 head:    2c70a0d845f9acc15144a2afec889370612cca66
              (cursor/fail-closed-linux-0b95)
#320 head:    34a89256e66037e97d52eb9d3e2c0da1267b56a7
              (cursor/jetson-proof-kit-fd7b)
Trees:        /tmp/review-c0-307-src/fail-closed-linux
              /tmp/review-c0-307-src/jetson-proof-kit
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64:      NOT RUN
Jetson:       NOT RUN
```

Earlier reviews (#314, #316) stopped at #307 `129fdc98` (hard ABI 5
floor). This session is the first independent look at the per-right
floor and at the kit that prints both floors.

## C0 fail-closed on this VM

The unmutated guard is fail-closed on this Linux x86_64, ABI 6 host.

It starts the static probe only after user namespace, capability drop,
`no_new_privs`, seccomp, and Landlock. A real `fcl-launch` of
`model-provider` printed `started`, then `socket_inet errno=1`,
`read_outside errno=13`, and `storage_write ok`. The same binary with
the kit's empty file stopped after confinement: exit 71,
`step execve: Exec format error (os error 8)`. No path started a
provider without the layers.

Simulated ABI 1 to 4 refuse for did, wallet, and model, and they name
the missing right and the ABI. Dropping that check (F-RV-F18 / #307
F18) starts the provider on ABI 1 inside `SimKernel`. That plant is
caught.

Aarch64 execution and the Jetson stay NOT RUN. This statement is for
this VM only.

## Verdicts

| ID | Claim | Verdict | Evidence |
| --- | --- | --- | --- |
| C0-1 | No path launches a provider when a required right is missing | **HOLDS** on this ABI 6 host and in `SimKernel` ABI 1–4 | `cargo test --locked`: lib 6, real 9, simulated 13, 0 ignored. F-RV-F18 starts ABI 1 only after the check is deleted |
| C0-2 | Every refusal names the missing right and the ABI | **HOLDS** for the default per-right path. **WEAK** when `--require-landlock-abi N` is set | Default ABI 1 text: `this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)`. `--require-landlock-abi 7` on this host: `Landlock ABI 6 is below the required 7` (no right name). Extra floor is checked first |
| C0-3 | The ABI-to-right table matches the kernel Landlock uapi and docs | **HOLDS** against Linux 6.12 uapi and the 6.12 "Previous limitations" page | truncate = ABI 3 / 6.2, ioctl_dev = ABI 5 / 6.10, scope = ABI 6 / 6.12, REFER omitted because it is already denied. Bit values `1<<14` and `1<<15` match v6.12 `landlock.h`. This VM's `/usr/include/linux/landlock.h` is older (no `IOCTL_DEV`, no `scoped`) and is not the oracle |
| C0-4 | On Linux 5.15 (ABI 1) the three providers cannot launch under any floor that still denies truncate | **HOLDS** as the guard's ABI-number policy. **WEAK** as a board or 5.15-kernel measurement | `SimKernel` ABI 1 refuses all three. 5.15 is below 5.19, so it is ABI 1 when Landlock is on. This session did not boot 5.15 or a Jetson. If the LSM is off the reason is `Landlock is not available`, not the named rights. Both refuse |
| C0-5 | The per-right floor is proven on the real kernel | **FALSIFIED** as a real-kernel row | The only real ABI test is `--require-landlock-abi host+1` (extra floor). ABI 1–4 run only in `SimKernel`. `SimKernel::landlock_add_path_rule` ignores the access mask, so it does not replay the kernel `EINVAL` that a real ABI 1 `add_rule` would return when the grant still contains `TRUNCATE` |
| C0-6 | The positive probe proves truncate and ioctl_dev are denied | **WEAK** | `probe/main.rs` never calls `truncate` or `ioctl`. It writes and reads a regular file. Device ioctl and outside `O_TRUNC` stay unmeasured on this host |
| C0-7 | An empty fault pipe is reported as a start | **WEAK** | Still in `real.rs`: `got == 0` returns `Ok(pid)`. The README already says so. Nothing runs. It is a misreport, not an unconfined exec |
| C0-8 | A skipped or NOT RUN #307 test is counted as a pass | **HOLDS** that it is not | No `#[ignore]`. `cargo test` printed `0 ignored`. A host without Landlock hits `assert!(abi > 0)` and fails |
| C0-9 | PID namespace and `LANDLOCK_SCOPE_SIGNAL` at ABI 5 are named gaps | **HOLDS** | The guard unshares only `CLONE_NEWUSER`. ABI 5 launches with `scoped == 0`. ABI 6 sets `SCOPE_SIGNAL` and fails closed if `create_ruleset` then fails |
| JPK-1 | The ABI 1 fixture exercises the #307 guard | **FALSIFIED** | `test_decisions.sh` calls `decide.py`. That file has no `fcl-launch`, no `fail_closed`, no `missing_required_mask`. README: "The table is computed from the measured facts. It does not depend on which C0 commit was fetched." |
| JPK-2 | The default C0 pin is the per-right floor | **FALSIFIED** | `JPK_C0_DEFAULT_SHA=129fdc98428c9029b328976511478c46ebe765a6`. That commit still has `LANDLOCK_ABI_FLOOR = 5`. Head `2c70a0d8` is used only with `JPK_C0_PR=307` |
| JPK-3 | Kit refusal reasons match #307 | **FALSIFIED** | Kit ABI 1 per-right: `missing TRUNCATE, IOCTL_DEV`. Guard: `this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)` |
| JPK-4 | A lying ABI 5 with ABI 1 rights matches the guard | **FALSIFIED** | Kit `per_right` refuses. #307 trusts the version query and would launch at reported ABI 5. A real kernel cannot report 5 without those rights. The fixture is a kit policy, not the guard |
| JPK-5 | `CAP_SETPCAP` is bit 8 | **FALSIFIED** | `probe_host.py` sets `CAP_SETPCAP = 21`. That is `CAP_SYS_ADMIN`. uapi `/usr/include/linux/capability.h`: `CAP_SETPCAP` is 8. `decide.py` falls back to `(1 << 21)`. On this host `CapBnd` has both bits, so the table still says droppable |
| JPK-6 | `C0.guard` is the three-provider, both-floor table from the binary | **FALSIFIED** | One launch: `--provider did-provider` and `: >"$exe"`. On this ABI 6 host that path is `step execve: Exec format error`. Wallet and model never run |
| JPK-7 | NOT RUN or SKIP is counted as a functional pass of the board | **HOLDS** that the committed file stays `NOT RUN` (30 honest rows). **WEAK** on live recording | `test_guards.sh` asserts each committed status is `NOT RUN`. `run-on-jetson.sh` then stamps `host.right.truncate PASS` even when the value is `absent EINVAL`, and stamps a `LAUNCH` decision as `PASS` |

## #307, fail-open hunt

`confine` probes the ABI, then:

1. extra floor (`abi < plan.abi_floor`), default 0
2. `missing_required_mask(abi)` for truncate (3) and ioctl_dev (5)
3. `create_ruleset` with only bits that ABI knows
4. path rules, then `restrict_self`
5. `exec` only after `Ok`

`--require-landlock-abi` can raise the extra floor. It cannot drop a
needed right. `sim_landlock_abi_floor_cannot_be_lowered` holds that.

F-RV-F18 deleted step 2. `SimKernel` then started `did-provider` on
ABI 1 (`pid 4242`, `Execve` in the step list). The four named tests
failed. On a real ABI 1 kernel, step 3 would still hand
`STORAGE_ROOT_ACCESS` (includes `TRUNCATE`) to `add_rule` while
`handled_fs` omits that bit, which is `EINVAL`. ABI 3 and 4 would
launch: truncate is handled and granted, ioctl_dev is not handled, so
device ioctl stays unrestricted. The explicit check is what stops
those ABIs. `SimKernel` does not model the kernel `EINVAL`.

No `env` switch turns a layer off. `launch` has no unconfined
restart. F01 in the crate still plants that restart.

## ABI table

Checked against
https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/landlock.h
and
https://www.kernel.org/doc/html/v6.12/userspace-api/landlock.html
("Previous limitations").

| Right | Bit | First ABI | First kernel | If omitted | #307 |
| --- | --- | --- | --- | --- | --- |
| REFER | `1<<13` | 2 | 5.19 | Already denied | not required |
| TRUNCATE | `1<<14` | 3 | 6.2 | Always allowed | required |
| NET bind/connect | `1<<0/1` | 4 | 6.7 | TCP only | not a launch right; seccomp denies `socket` |
| IOCTL_DEV | `1<<15` | 5 | 6.10 | Always allowed | required |
| SCOPE_SIGNAL | `1<<1` | 6 | 6.12 | Unset is wider | set at ABI 6; ABI 5 launches (named gap) |

5.15 is ABI 1 when Landlock is present. There is no floor that both
starts the three providers on ABI 1 and still denies truncate. That
sentence holds. Calling JetPack R36.4.7 / `5.15.148-tegra` "ABI 1"
without a board probe overstates the measurement. The honest board
row is still NOT RUN.

## #320, the kit

The printed table is `decide.py`. The ABI 1 fixture is a facts file.
`JPK_FACTS` reprints it. None of that links `fcl-launch` or
`confine`. F-JPK-ABI plants `landlock_abi_value` so every kernel is
ABI 6; that breaks `abi1_did_abi5` in `decide.py`, not in #307.

Default fetch of C0 is the old hard floor. `JPK_C0_PR=307` fetches
the current head and is documented. An operator who runs the script
as written builds `129fdc98`.

`CAP_SETPCAP = 21` is a real kit bug. It does not open a #307 launch
on this host.

## Tests this session

```text
#307, writable copy of 2c70a0d8, CARGO_TARGET_DIR under /tmp:
cargo test --locked
  lib 6 passed, 0 ignored
  real_kernel 9 passed, 0 ignored
  simulated 13 passed, 0 ignored

#320, tests from the read-only tree / a writable copy:
bash tests/test_guards.sh     summary 56 passed 0 failed
bash tests/test_decisions.sh  summary 39 passed 0 failed
bash falsify.sh               3 CAUGHT of 3

This folder:
python3 lab/review-c0-307/check.py
python3 lab/review-c0-307/test_review.py
python3 lab/review-c0-307/falsify.py
  F-RV-F18 CAUGHT (ABI 1 launched after the missing-right check was dropped)
  F-RV-CAP CAUGHT
  F-RV-COPY CAUGHT

Live on this host:
fcl-launch --provider model-provider -- <static probe>  -> started, confined
fcl-launch --provider did-provider -- <empty file>      -> 71, execve os error 8
fcl-launch --require-landlock-abi 7                     -> 71, ABI 6 below 7
decide.py on live facts                                 -> LAUNCH / LAUNCH
decide.py on abi-1-jetson.facts                         -> REFUSE / REFUSE
```

`#307` `python3 falsify.py` (18 plants) was not re-run this session.
F18 was replayed as F-RV-F18. The 18-plant claim stays unverified
here.

## Fix list for #307

1. Add a real-kernel row that the extra floor is not the per-right
   floor. Today `real_landlock_abi_below_required_refuses` only
   covers `--require-landlock-abi`.
2. Make `SimKernel::landlock_add_path_rule` refuse when `access` is
   not a subset of `handled_fs`. Then F18 on ABI 1 would stop at
   `storage_root_rule`, and ABI 3–4 would still catch a silent drop
   of `ioctl_dev`.
3. Keep the extra-floor reason from hiding a missing right: if both
   apply, name the right.
4. Add probe rows for outside `truncate` / `O_TRUNC` and for `ioctl`
   on a planted device node. Do not treat "ABI >= 5" as that proof.
5. Keep the empty-pipe start as a named limit, or write a short
   record before `_exit` on every path.

## Fix list for #320

1. Drive the table from `fcl-launch` or from
   `fail_closed_linux::file_profile_launches_on_abi` /
   `missing_rights_reason`. Delete the parallel policy in
   `decide.py`, or mark it as a kit estimate.
2. Pin `JPK_C0_DEFAULT_SHA` to `2c70a0d8`, or refuse to print a
   per-right table against the old floor.
3. Copy #307's reason text (right + ABI). Stop saying
   `missing TRUNCATE, IOCTL_DEV` as if the guard printed it.
4. Set `CAP_SETPCAP = 8`. Add a test that bit 21 is not the check.
5. Launch a real stand-in, not `: >"$exe"`. Record did, wallet, and
   model. Do not stamp `C0.guard REFUSED` for `ENOEXEC`.
6. Stamp a measured-absent right as `REFUSED` or `ABSENT`, not
   `PASS`. Keep committed Jetson rows as `NOT RUN`.

## For Sash or Anders

1. Keep `ioctl_dev` as a launch requirement? That is a policy choice.
   It forces ABI 5, so Jetson-class 5.15 still refuses. Dropping it
   would allow ABI 3–4 (Linux 6.2–6.9) while device ioctl stayed
   unrestricted. Truncate alone still blocks 5.15.
2. Accept PID namespace and ABI-5 `SCOPE_SIGNAL` as named gaps for
   C0, or block ABI 5 until a grandchild PID namespace exists.
3. Should the kit be a measurement of #307, or a separate policy
   oracle? Today it is the second, and it pins the old floor.
4. Empty fault pipe reported as a start: fix in C0, or leave as the
   documented `Command` limit.

## Next

@irzhyran reviews #307 against this report. #320 follows the same
fix list. This PR stays draft. Aarch64 and the Jetson stay NOT RUN
until those machines produce their own rows.
