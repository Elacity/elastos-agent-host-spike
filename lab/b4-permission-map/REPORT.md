# B4 permission map

```text
Slice:        lab/b4-permission-map (M1 check B4, static half + proposed baseline)
Branch / PR:  cursor/b4-permission-map-4cfd  https://github.com/Elacity/elastos-agent-host-spike/pull/330
Commit:       d2310e2d5abff0fdafb08c52ec5d24f21d3cce55   parent d006fa0147084942553dba1d0121c0f6985eab0e
Develop:      Elacity develop not merged: this PR only adds lab/b4-permission-map/
Machine:      Linux x86_64, kernel 6.12.94+, python3, rustc unused
```

## Invariant

The same declared rights for did, wallet, and model produce one comparison
table on macOS and on Linux. A right allowed on one platform and denied on
the other, or enforced on one and missing on the other, is a named mismatch
with `file:line` on both sides.

`baseline.json` declares each comparison right once, including a
`STORAGE_PARENT` right and one polarity for `/` and `sysctl-read`. The
checker scores every platform against that file (`CONFORMS` /
`MUST CHANGE` / `OPEN DECISION`) and still compares the platforms to each
other. Where a polarity is unsure, the file proposes the tighter side and
marks the row open for Sash and Anders.

## What this lab reads

macOS, on this branch, read-only:

- `capsules/{did,wallet,model}-provider/confine.sb`
- `capsules/{did,wallet,model}-provider/tests/fixtures/confine/declared-rights.json`
- the operations tables under `## Operations and the rights they need`

Linux, fetched by SHA (those folders are not on `spike/agent-host`):

- draft PR #296 `lab/linux-confine` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`
- draft PR #307 `lab/fail-closed-linux` at `2c70a0d845f9acc15144a2afec889370612cca66`

C8 already owns the bridge-contract template. This lab consumes
`storage`, `bound-executable`, `startup-root-directory`, and
`startup-sysctl` from that template. It does not add a second one. The
other rows are the implicit denials of `(deny default)` and
`(deny network*)`. `baseline.json` is a proposal scored against those
rows. It is not a second C8 template and it does not edit a profile.

## Per-right decision

| Right | Proposed | Decision | macOS | #296 | #307 | Who changes if the proposal is adopted |
| --- | --- | --- | --- | --- | --- | --- |
| `bound-executable` | allow | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `storage.root` | allow | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `storage.parent` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop the STORAGE_PARENT literal and split it out of C8 storage |
| `startup-root-directory` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop the `/` pin |
| `startup-sysctl` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop `sysctl-read` |
| `outside.read` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `outside.write` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `network` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `unix-socketpair` | deny | proposed | CONFORMS | MUST CHANGE | CONFORMS | #296: drop the AF_UNIX socketpair exception |
| `exec.other` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `signal.host` | deny | proposed | CONFORMS | CONFORMS | MUST CHANGE | #307: unshare `CLONE_NEWPID` |
| `device.ioctl` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |

Full text is `BASELINE.md`. Inter-platform mismatch rows stay 30 in
`MISMATCHES.md`.

## Counts

- CONFORMS: **75**
- MUST CHANGE: **6** (`unix-socketpair` on #296 and `signal.host` on #307, each on three providers)
- OPEN DECISION: **27** (`storage.parent`, `startup-root-directory`, `startup-sysctl` × 3 providers × 3 platforms)
- Inter-platform mismatch rows: **30**

Counts are provider × right × platform (3 × 12 × 3 = 108).

## Open decisions

For Sash and Anders:

1. `storage.parent` — proposed deny of a host-parent grant. Landlock cannot
   name a directory alone. The keep-the-right path is the #296 wallet
   remount on every provider.
2. `startup-root-directory` — proposed deny of `/` as a shared right. A
   Landlock rule on `/` grants the whole tree. Open until a named test
   shows the macOS loader starts without that pin, or the pin is classed
   as macOS-loader-only.
3. `startup-sysctl` — proposed deny of `sysctl-read` as a shared right.
   Linux has no sysctl grant. Open until a named test shows the macOS
   loader starts without it, or the Linux loader syscalls stay Linux-only.

## Checker and falsifier

```text
python3 -I lab/b4-permission-map/check.py --write   -> wrote tables, MISMATCHES.md, BASELINE.md
python3 -I lab/b4-permission-map/check.py --check   -> tables, MISMATCHES.md, and BASELINE.md match the sources
python3 -I -m unittest discover -s lab/b4-permission-map/tests -v
python3 -I lab/b4-permission-map/check.py --plant lab/b4-permission-map/plants/macos-network-allow
  -> F-B4-MACOS-NETWORK-ALLOW CAUGHT (did-provider/network/polarity)
python3 -I lab/b4-permission-map/check.py --plant-baseline lab/b4-permission-map/plants/baseline-network-allow
  -> F-B4-BASELINE-NETWORK-ALLOW CAUGHT (network/MUST CHANGE)
```

Falsifiers:

- `plants/macos-network-allow/confine.sb` is a copy of the did oracle
  with `(allow network*)` appended. The checker reports a polarity
  mismatch against both Linux labs. A control copy without that line is
  not a network CATCH.
- `plants/baseline-network-allow/overlay.json` proposes `network` allow
  on the committed baseline. Platforms that deny sockets score
  MUST CHANGE. The committed baseline is not a network CATCH.
  Break: `matches_proposal` treated every verdict as allow. Then
  `test_looser_network_overlay_is_caught` failed and the CLI printed
  `F-B4-BASELINE-NETWORK-ALLOW SURVIVED`. Reverted.

## Not run here

- Linux x86-64 execution: **NOT RUN**
- Jetson aarch64 execution: **NOT RUN**
- macOS `sandbox-exec` execution: **NOT RUN**

This checker is static. It does not start a provider, install Landlock,
or run Seatbelt.

## What B4 still needs

B4 is not closed. The map names the gaps. The baseline proposes one
polarity per right. It does not apply a fix.

1. Sash and Anders close the three OPEN DECISION rows above.
2. #296 drops the AF_UNIX `socketpair` exception (MUST CHANGE).
3. #307 unshares `CLONE_NEWPID` (MUST CHANGE).
4. Linux x86-64 and Jetson execution of the #296 / #307 launchers.
   Those stay with those labs and with the Linux matrix.
5. The Runtime generator that emits both profiles from the C8
   declared-rights input. That bridge is still not built.

Fixes belong in the owning folders. This lab does not apply them.

## Principles

- 3 No ambient authority: a right that one platform grants and the
  other omits is listed, and the baseline proposes the tighter side.
- 10 One canonical path: the C8 template stays the one declared-rights
  source. `baseline.json` is a scored proposal, not a second template.
- 11 Fail closed: a planted network allow is CATCH; a planted looser
  baseline is CATCH; a missing pin is a read error. Unsure polarities
  stay open.
- 12 Docs, code, tests agree: `--check` refuses a stale table or
  `BASELINE.md`.

## DeepSeek

none

## Questions

Sash and Anders: the three OPEN DECISION rows.
