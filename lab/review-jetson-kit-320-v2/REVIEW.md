# Adversarial review of #320 v2 (Jetson proof kit)

Draft only. Do not merge. This folder does not edit
`lab/jetson-proof-kit/` or `lab/fail-closed-linux/`.

```text
Lane:         lab/review-jetson-kit-320-v2
Reviewed:     Elacity/elastos-agent-host-spike#320
Review PR:    Elacity/elastos-agent-host-spike#345
#320 head:    2bb0b5859bbf8582a43d958e3ddc1569eb77bf97
              (cursor/jetson-proof-kit-fd7b)
#307 pin:     2c70a0d845f9acc15144a2afec889370612cca66
              (cursor/fail-closed-linux-0b95)
C9 pin:       2dc3c565c6649d668f1e50efefeea7d964330f9c
              (cursor/linux-confine-e156)
Trees:        /tmp/jpk-320  /tmp/c0-307  /tmp/c9-296
Machine:      Linux 6.12.94+ x86_64, rustc 1.91.0, Landlock ABI 6, uid 1000
Aarch64:      NOT RUN
Jetson:       NOT RUN
```

Earlier review #338 read #320 at `34a89256` and falsified JPK-1 through
JPK-6. This session reads the claimed fix commit only.

## Verdicts

| ID | Claim | Verdict |
| --- | --- | --- |
| JPK-1 | `decide.py` is a labeled #307 oracle; the live script also runs `fcl-launch` for did, wallet, and model | **CONFIRMED** |
| JPK-2 | Default C0 pin is `2c70a0d8`; `--pin 129fdc98` refuses the per-right column | **CONFIRMED** |
| JPK-3 | Refusal text is #307 `missing_rights_reason` | **CONFIRMED** |
| JPK-4 | #307 trusts the ABI number; a lying ABI 5 launches under `per_right`; measured rights are named | **CONFIRMED** |
| JPK-5 | `CAP_SETPCAP = 8`; bit 21 is `CAP_SYS_ADMIN` and is not the check | **CONFIRMED** |
| JPK-6 | Real static stand-in for each provider; `Exec format error` / `os error 8` stamps `NOT RUN` | **CONFIRMED** |
| JPK-7 | Measured-absent rights stamp `ABSENT`, never `PASS` | **CONFIRMED** |

Live `fcl-launch` of the three providers was not executed here. The
script contains those three calls. Aarch64 and the Jetson stay NOT RUN.

## JPK-1

`decide.py` says it is not the guard and names
`2c70a0d845f9acc15144a2afec889370612cca66`. `run-on-jetson.sh` calls
`jpk_run_c0_provider` for did, wallet, and model with
`--provider ${name}-provider` and a stand-in path.

The named kit tests (`decide_labeled_oracle`,
`script_launches_{did,wallet,model}`) are string checks. They do not
start `fcl-launch`. That is enough for the written claim. It is not a
board run of the guard.

## JPK-2

`lib.sh` sets `JPK_C0_DEFAULT_SHA` to
`2c70a0d845f9acc15144a2afec889370612cca66`.
`decide.per_right_table_allowed("129fdc98428c9029b328976511478c46ebe765a6")`
is false. The old pin still prints the ABI 5 column.

## JPK-3

#307 `missing_rights_reason` at `2c70a0d8`:

```text
this kernel's Landlock ABI {abi} cannot deny {name} (needs ABI {n}); ...
```

`decide.py` prints the same bytes for ABI 1 through 4. The ABI 1
fixture reason is exactly:

```text
this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5)
```

A named gap, not a failed claim: #307 `AbiProbe` adds the OS error
(`Landlock is not available: ...`). The oracle prints
`Landlock is not available`.

## JPK-4

#307 `confine` takes `abi` from `kernel.landlock_abi()`, then
`missing_required_mask(abi)`. `real.rs` `landlock_abi` is the version
query only (`landlock_create_ruleset(NULL, 0, CREATE_RULESET_VERSION)`).
It does not read measured truncate or ioctl_dev.

`file_profile_launches_on_abi(5)` is true. `file_profile_launches_on_abi(1)`
is false. The kit's lying fixture therefore launches under `per_right`,
and the reason says the guard trusts the ABI number and that measured
truncate and ioctl_dev are absent. That honesty line is kit-only.
#307 would print `started` and would not name the measured rights.

## JPK-5

`/usr/include/linux/capability.h`: `CAP_SETPCAP` is 8,
`CAP_SYS_ADMIN` is 21. `probe_host.py` and `decide.py` both use 8.
Mask `(1 << 8)` is droppable. Mask `(1 << 21)` is not the check.

## JPK-6

The empty `: >"$exe"` path is gone. `jpk_c0_standin` prefers
#307's `fcl-probe`, then compiles `standin.rs` with
`-C target-feature=+crt-static`. `jpk_classify_c0_launch` stamps
`Exec format error` / `os error 8` as `NOT RUN`.

This host compiled `standin.rs` to a static-pie ELF. `ldd` printed
`statically linked`. That is this x86_64 host, not the Jetson.

## JPK-7

`jpk_availability_status` maps `absent` to `ABSENT`, `available` to
`PASS`, and anything else to `REFUSED`. The ABI 1 fixture records
`host.right.truncate` and `host.right.ioctl_dev` as `ABSENT`. The 33
committed evidence rows stay `NOT RUN`.

A `LAUNCH` oracle row is still stamped `PASS`. That is a decision
row, not a measured-absent right.

## Safety (live Jetson)

| Guard | Verdict |
| --- | --- |
| Writes stay under `~/flint-elastos-test` for kit-owned paths | **CONFIRMED** |
| `TMPDIR` is unset, so cargo/rustc/gcc may write temps in `/tmp` | **FALSIFIED** as complete write containment |
| Cargo jobs are `-j 4` | **CONFIRMED** |
| gcc uses four jobs | **FALSIFIED** (invoked without `-j`; safer) |
| Stop below 1 GiB `MemAvailable` | **CONFIRMED** for the check; **WEAK** for the kill (cargo only, not the process group) |
| Never names pc2.net, PM2, port 4200, sudo, apt | **CONFIRMED** in the kit |
| No apt/pip/npm install | **CONFIRMED** |
| Refuses to run as root | **UNTESTED** (no uid 0 check) |
| No network | **FALSIFIED** as offline: default git remote is GitHub; `cargo build --locked` may fetch crates.io into `CARGO_HOME` under the folder |

C9: the kit runs `lc-setup` with no policy path. At the pinned C9
commit that path refuses (`the launch has no policy` or the ABI
floor) and does not exec the probe. It does not unshare or mount.

`fcl-probe`, if chosen as the stand-in and started unconfined, binds
`127.0.0.1:0` and reads `/etc/passwd`. Under a working #307 guard
those calls fail. That is not pc2.net or port 4200.

## Go / no-go

**GO** for an unprivileged operator who copies the kit to
`~/flint-elastos-test` and runs `./run-on-jetson.sh`.

Do not run it as root. The script will contact GitHub and may
contact crates.io unless `JPK_REMOTE` points at a local clone and a
cargo cache is already under the folder. A missing tool or a failed
fetch is a `REFUSED` / `NOT RUN` row, not an apt step.

**NO-GO** as root, and **NO-GO** if the board must stay fully
offline while C0 is still expected to build.

## Tests this session

```text
bash /tmp/jpk-320/lab/jetson-proof-kit/tests/test_guards.sh
  summary 74 passed 0 failed
bash /tmp/jpk-320/lab/jetson-proof-kit/tests/test_decisions.sh
  summary 55 passed 0 failed
bash /tmp/jpk-320/lab/jetson-proof-kit/falsify.sh
  F-JPK-OUTSIDE CAUGHT
  F-JPK-MEM CAUGHT
  F-JPK-ABI CAUGHT
  F-JPK-CAP CAUGHT
  F-JPK-REASON CAUGHT
  F-JPK-LIE CAUGHT
  F-JPK-ABSENT CAUGHT
  summary 7 CAUGHT of 7
python3 -I lab/review-jetson-kit-320-v2/check.py
  summary 54 passed 0 failed
bash lab/review-jetson-kit-320-v2/falsify.sh
  F-RV-ORACLE CAUGHT
  F-RV-PIN CAUGHT
  F-RV-REASON CAUGHT
  F-RV-LIE CAUGHT
  F-RV-ENOEXEC CAUGHT
  F-RV-JOBS CAUGHT
  F-RV-PC2 CAUGHT
  summary 7 CAUGHT of 7

This host:
  rustc standin.rs -C target-feature=+crt-static
    static-pie linked; ldd: statically linked
```

`#307` `cargo test` and a live `fcl-launch` were not re-run. The
reason-text and lying-ABI checks used the #307 source at `2c70a0d8`.

## New falsifiers

Plants run on copies. The #320 tree stays unchanged.

| ID | Plant | Caught by |
| --- | --- | --- |
| F-RV-ORACLE | drop the oracle label | `jpk1_labeled_oracle` |
| F-RV-PIN | default pin back to `129fdc98` | `jpk2_default_pin` |
| F-RV-REASON | old `missing TRUNCATE, IOCTL_DEV` text | `jpk3_reason_abi1` |
| F-RV-LIE | per_right uses measured rights | `jpk4_lie_launches` |
| F-RV-ENOEXEC | Exec format error stamps `REFUSED` | `jpk6_classify_exec_format` |
| F-RV-JOBS | `JPK_BUILD_JOBS=8` | `safety_jobs_4` |
| F-RV-PC2 | name `pc2.net` in the operator script | `safety_no_pc2_net` |

## For Sash or Anders

1. Accept compiler temps in `/tmp`, or set `TMPDIR` under
   `~/flint-elastos-test` before cargo/rustc/gcc.
2. Accept the missing uid 0 refusal, or add it.
3. The kit is both a #307 oracle and a later `fcl-launch` measurement.
   The printed table is still the oracle. The live guard is the three
   `C0.guard.*` rows.

## Next

A human copies the kit to the Jetson and runs `./run-on-jetson.sh`
as an unprivileged user. This PR stays draft. Aarch64 and the Jetson
stay NOT RUN until that board writes its own rows.
